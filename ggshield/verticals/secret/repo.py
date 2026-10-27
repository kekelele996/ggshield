import itertools
import logging
import traceback
from collections.abc import Iterable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from re import Pattern
from typing import Callable, List, Optional, Set, Tuple

from click import UsageError
from pygitguardian import GGClient

from ggshield.core import ui
from ggshield.core.cache import Cache
from ggshield.core.client import check_client_api_key
from ggshield.core.config import Config
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.constants import MAX_WORKERS
from ggshield.core.errors import ExitCode, QuotaLimitReachedError, handle_exception
from ggshield.core.scan import Commit, ScanContext
from ggshield.core.scan_progress import ScanProgress
from ggshield.core.scanner_ui import create_message_only_scanner_ui
from ggshield.core.text_utils import STYLE, format_text, pluralize
from ggshield.utils.git_shell import get_list_commit_SHA, is_git_dir
from ggshield.utils.os import cd
from ggshield.verticals.secret.secret_scanner import (
    get_required_token_scopes_from_config,
)

from .output import SecretOutputHandler
from .secret_scan_collection import Results, SecretScanCollection
from .secret_scanner import SecretScanner


logger = logging.getLogger(__name__)


# We add a maximal value to avoid silently consuming all threads on powerful machines
SCAN_THREADS = 4


def scan_repo_path(
    client: GGClient,
    cache: Cache,
    output_handler: SecretOutputHandler,
    exclusion_regexes: Set[Pattern[str]],
    config: Config,
    scan_context: ScanContext,
    repo_path: Path,
) -> int:  # pragma: no cover
    try:
        if not is_git_dir(repo_path):
            raise UsageError(f"{repo_path} is not a git repository")

        with cd(repo_path):
            progress = ScanProgress.create(
                client=client,
                scan_context=scan_context,
                secret_config=config.user_config.secret,
                exclusion_regexes=exclusion_regexes,
            )
            return scan_commit_range(
                client=client,
                cache=cache,
                commit_list=get_list_commit_SHA("--all"),
                output_handler=output_handler,
                exclusion_regexes=exclusion_regexes,
                scan_context=scan_context,
                secret_config=config.user_config.secret,
                progress=progress,
            )
    except Exception as error:
        return handle_exception(error)


def scan_commits_content(
    commits: List[Commit],
    client: GGClient,
    cache: Cache,
    scan_context: ScanContext,
    secret_config: SecretConfig,
    progress_callback: Callable[[int], None],
    commit_scanned_callback: Callable[[Commit], None],
) -> SecretScanCollection:  # pragma: no cover
    try:
        commit_files = itertools.chain.from_iterable(c.get_files() for c in commits)

        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=scan_context,
            check_api_key=False,  # Key has been checked in `scan_commit_range()`
            secret_config=secret_config,
        )
        with create_message_only_scanner_ui() as scanner_ui:
            results = scanner.scan(
                commit_files, scan_threads=SCAN_THREADS, scanner_ui=scanner_ui
            )
    except QuotaLimitReachedError:
        raise
    except Exception as exc:
        logger.error(
            "Exception raised during scan. commits=%s type(exception)=%s exception=%s trace=%s",
            commits,
            type(exc),
            exc,
            traceback.format_exc(),
        )
        results = Results.from_exception(exc)
    finally:
        progress_callback(len(commits))
        for commit in commits:
            commit_scanned_callback(commit)

    result_for_urls = {result.url: result for result in results.results}
    scans = []
    for commit in commits:
        results_for_commit_files = [
            result_for_urls[u] for u in commit.urls if u in result_for_urls
        ]

        optional_header = (
            format_text(f"\ncommit {commit.sha}\n", STYLE["commit_info"])
            + f"Author: {commit.info.author} <{commit.info.email}>\n"
            + f"Date: {commit.info.date}\n"
        )

        scans.append(
            SecretScanCollection(
                commit.sha or "unknown",
                type="commit",
                results=Results(
                    results=results_for_commit_files,
                    errors=results.errors,
                ),
                optional_header=optional_header,
                extra_info={
                    "author": commit.info.author,
                    "email": commit.info.email,
                    "date": commit.info.date,
                },
            )
        )

    return SecretScanCollection(
        id=scan_context.command_id, type="commit-ranges", scans=scans
    )


def get_commits_by_batch(
    commits: Iterable[Commit],
    batch_max_size: int,
) -> Iterator[List[Commit]]:
    """
    Given a list of commit shas yield the commit files
    by biggest batches possible of length at most `batch_max_size`
    """
    current_count = 0
    batch = []
    for commit in commits:
        num_files = len(commit.urls)
        if current_count + num_files < batch_max_size:
            batch.append(commit)
            current_count += num_files
        else:
            # The first batch can remain empty if it has too many files
            if batch:
                yield batch
            current_count = num_files
            batch = [commit]
    # Send the last batch that remains
    yield batch


def scan_commit_range(
    client: GGClient,
    cache: Cache,
    commit_list: List[str],
    output_handler: SecretOutputHandler,
    exclusion_regexes: Set[Pattern[str]],
    scan_context: ScanContext,
    secret_config: SecretConfig,
    include_staged: bool = False,
    progress: Optional[ScanProgress] = None,
) -> ExitCode:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_list: List of commits sha to scan
    :param verbose: Display successful scan's message
    :param progress: When provided, commits recorded as already scanned in it
        are skipped and the state is updated after each batch, which allows
        interrupted scans to resume without scanning the same commits twice.
    """
    check_client_api_key(client, get_required_token_scopes_from_config(secret_config))
    max_documents = client.secret_scan_preferences.maximum_documents_per_scan

    commits_to_scan = commit_list
    if progress is not None:
        commits_to_scan = progress.plan(commit_list)
        if progress.resumed_count or progress.retried_count:
            ui.display_verbose(
                f"Resuming scan: {progress.resumed_count} already scanned "
                f"commit(s) skipped, {progress.retried_count} previously failed "
                "commit(s) will be retried."
            )

    with ui.create_progress(len(commit_list) + int(include_staged)) as progress_bar:
        # Already scanned commits are completed work, advance the bar at once.
        if progress is not None:
            progress_bar.advance(progress.resumed_count)

        commits_iters: list[Iterable[Commit]] = []
        if include_staged:
            commits_iters.append(
                (Commit.from_staged(exclusion_regexes=exclusion_regexes),)
            )
        commits_iters.append(
            Commit.from_sha(sha, exclusion_regexes=exclusion_regexes)
            for sha in commits_to_scan
        )
        commits_batch = get_commits_by_batch(
            commits=itertools.chain(*commits_iters),
            batch_max_size=max_documents,
        )
        scans: List[SecretScanCollection] = []

        def commit_scanned_callback(commit: Commit):
            if include_staged and commit.sha is None:
                ui.display_verbose("Scanned staged changes")
            else:
                ui.display_verbose(f"Scanned {commit.sha}")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Track the commits of each future so progress can be recorded per
            # batch in submission order.
            futures: List[Tuple[Future, List[Commit]]] = []
            for commits in commits_batch:
                # The last batch can be empty when every commit was already
                # scanned: don't submit a useless scan for it.
                if not commits:
                    continue
                futures.append(
                    (
                        executor.submit(
                            scan_commits_content,
                            commits,
                            client,
                            cache,
                            scan_context,
                            secret_config,
                            progress_bar.advance,
                            commit_scanned_callback,
                        ),
                        commits,
                    )
                )

            try:
                # in submission order so we preserve the order
                for future, batch_commits in futures:
                    try:
                        scan_collection = future.result()
                    except Exception as exc:
                        # Persist the interrupted batch as failed so the next
                        # run retries it; in-flight batches stay untracked and
                        # are simply scanned again.
                        if progress is not None:
                            progress.mark_failed(
                                _commit_shas(batch_commits),
                                str(exc) or exc.__class__.__name__,
                            )
                        raise
                    batch_errors: List[str] = []
                    for scan in scan_collection.scans_with_results:
                        if scan.results and scan.results.errors:
                            for error in scan.results.errors:
                                ui.display_error(error.description)
                                batch_errors.append(error.description)
                        scans.append(scan)
                    if progress is not None:
                        batch_shas = _commit_shas(batch_commits)
                        if batch_errors:
                            progress.mark_failed(batch_shas, batch_errors[0])
                        else:
                            progress.mark_completed(batch_shas)
            except Exception:
                # Don't run the remaining batches if one already failed
                executor.shutdown(cancel_futures=True)
                raise

    if progress is not None and (progress.resumed_count or progress.retried_count):
        ui.display_info(
            f"Resumed scan: skipped {progress.resumed_count} previously scanned "
            f"{pluralize('commit', progress.resumed_count)}, retried "
            f"{progress.retried_count} previously failed "
            f"{pluralize('commit', progress.retried_count)}."
        )

    return_code = output_handler.process_scan(
        SecretScanCollection(
            id=scan_context.command_id, type="commit-range", scans=scans
        )
    )
    return return_code


def _commit_shas(commits: List[Commit]) -> List[str]:
    """Return the non-None SHAs (i.e. excluding staged changes) of a batch."""
    return [commit.sha for commit in commits if commit.sha is not None]
