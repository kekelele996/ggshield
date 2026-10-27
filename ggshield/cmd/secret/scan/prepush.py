import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Set

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import (
    GitUsage,
    exception_wrapper,
    non_blocking_on_server_error,
    uses_git,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.git_hooks.prepush import (
    PushRef,
    collect_push_refs,
    find_branch_start,
)
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import (
    EMPTY_TREE,
    check_git_dir,
    get_list_commit_SHA,
    is_valid_git_commit_ref,
)
from ggshield.verticals.secret.repo import scan_commit_range
from ggshield.verticals.secret.secret_scan_collection import SecretScanCollection


logger = logging.getLogger(__name__)


@dataclass
class _RefScan:
    """Commits which are going to be scanned for a single pushed ref."""

    push_ref: PushRef
    commit_list: List[str]


def _get_ref_commit_list(
    push_ref: PushRef, remote_name: str, max_commits: int
) -> List[str]:
    """
    Resolve the (possibly capped) list of new commits introduced by a single
    ref update. Returns an empty list if the range cannot be resolved or if the
    ref does not contain any new commit.
    """
    if push_ref.is_new_tree:
        # Ref reported as new by the pre-commit framework: scan the history
        # leading to the local commit.
        ui.display_info(f"New tree event. Scanning last {max_commits} commits.")
        before = EMPTY_TREE
        after = push_ref.local_commit
        cmd_range = f"{EMPTY_TREE} {push_ref.local_commit}"
    elif push_ref.precommit_env or is_valid_git_commit_ref(push_ref.remote_commit):
        # The pre-commit framework already resolves the range bounds. For the
        # hook stdin, this is an update of an existing remote ref.
        before = push_ref.remote_commit
        after = push_ref.local_commit
        cmd_range = f"{before}...{after}"
    else:
        # New ref pushed through the hook stdin: only scan commits which are
        # not available on the remote yet.
        start_commit = find_branch_start(push_ref.local_commit, remote_name)
        if start_commit is None:
            # The ref does not contain any new commit
            before = after = push_ref.local_commit
        else:
            before = f"{start_commit}~1"
            after = push_ref.local_commit
        cmd_range = f"{before}...{after}"

    commit_list = get_list_commit_SHA(cmd_range, max_count=max_commits + 1)

    if not commit_list:
        ui.display_warning(
            "Unable to get commit range.\n"
            f"  ref: {push_ref.name}\n"
            f"  before: {before}\n"
            f"  after: {after}\n"
            "Skipping this ref\n",
        )
        return []

    if len(commit_list) > max_commits:
        ui.display_info(f"Too many commits. Scanning last {max_commits} commits\n")
        commit_list = commit_list[-max_commits:]

    return commit_list


def _collect_failing_commits(
    scan_collection: SecretScanCollection,
) -> Set[str]:
    """
    Return the set of commit SHAs for which the scan reported secrets.
    """
    failing_commits: Set[str] = set()
    for commit_scan in scan_collection.scans_with_results:
        if commit_scan.results is not None and commit_scan.results.has_secrets:
            failing_commits.add(commit_scan.id)
    return failing_commits


@uses_git(GitUsage.REQUIRED)
@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
@non_blocking_on_server_error
def prepush_cmd(ctx: click.Context, prepush_args: List[str], **kwargs: Any) -> int:
    """
    Scan as a pre-push git hook all commits that are about to be pushed.

    Every ref update of the push (multiple branches, tags or mirror pushes) is
    taken into account. Commits shared by several refs are only scanned once.
    The push is blocked if any ref introduces a secret.
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config

    if check_user_requested_skip():
        return 0

    push_refs = collect_push_refs(prepush_args)
    logger.debug("refs=%s", push_refs)

    if not push_refs:
        ui.display_info("Deletion event or nothing to scan.")
        return 0

    # The pre-commit framework only passes a single update through environment
    # variables and does not give the remote name; the stdin path always does.
    remote_name = prepush_args[0] if prepush_args else "origin"
    max_commits = config.user_config.max_commits_for_hook
    ref_scans: List[_RefScan] = []

    for push_ref in push_refs:
        if push_ref.is_deletion:
            if push_ref.local_ref == "" and push_ref.remote_ref == "":
                # Single deletion reported through the pre-commit framework
                ui.display_info("Deletion event or nothing to scan.")
                return 0
            ui.display_info(f"{push_ref.name}: remote ref deleted, nothing to scan.")
            continue

        commit_list = _get_ref_commit_list(push_ref, remote_name, max_commits)
        if not commit_list:
            continue

        ui.display_info(f"{push_ref.name}: {len(commit_list)} new commit(s) to scan.")
        ref_scans.append(_RefScan(push_ref=push_ref, commit_list=commit_list))

    if not ref_scans:
        return 0

    # A commit can be pushed through several refs (merged or newly forked
    # branches): deduplicate them so each commit is scanned only once.
    commit_list: List[str] = []
    seen_commits: Set[str] = set()
    for ref_scan in ref_scans:
        for sha in ref_scan.commit_list:
            if sha in seen_commits:
                continue
            seen_commits.add(sha)
            commit_list.append(sha)

    ui.display_verbose(f"Commits to scan: {len(commit_list)}")

    check_git_dir()

    scan_context = ScanContext(
        scan_mode=ScanMode.PRE_PUSH,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
        endpoint_registration=config.user_config.endpoint_registration,
    )

    failing_commits: Set[str] = set()

    def scan_collection_callback(collection: SecretScanCollection) -> None:
        failing_commits.update(_collect_failing_commits(collection))

    return_code = scan_commit_range(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        commit_list=commit_list,
        output_handler=create_output_handler(ctx),
        exclusion_regexes=ctx_obj.exclusion_regexes,
        secret_config=config.user_config.secret,
        scan_context=scan_context,
        scan_collection_callback=scan_collection_callback,
    )

    # Report the check result of every ref that had commits to scan. If the
    # scan failed but no offending commit could be identified, consider all
    # refs as failing rather than letting the push through.
    unknown_failure = bool(return_code) and not failing_commits
    for ref_scan in ref_scans:
        ref_name = ref_scan.push_ref.name
        bad_commits = sorted(set(ref_scan.commit_list) & failing_commits)
        if bad_commits:
            short_shas = ", ".join(sha[:8] for sha in bad_commits)
            ui.display_error(
                f"{ref_name}: secret(s) found in commit(s) {short_shas}. "
                "Push to this ref rejected."
            )
        elif unknown_failure:
            ui.display_error(f"{ref_name}: scan failed. Push to this ref rejected.")
        else:
            ui.display_info(
                f"{ref_name}: {len(ref_scan.commit_list)} commit(s) scanned, "
                "no secrets found."
            )

    if return_code:
        ui.display_info(ctx_obj.client.remediation_messages.pre_push)
    return return_code
