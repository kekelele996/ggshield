import time
from copy import deepcopy
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import Commit, ScanContext, ScanMode
from ggshield.core.scan.commit_information import CommitInformation
from ggshield.core.scan.commit_utils import CommitScannable
from ggshield.core.scan_progress import ScanProgress
from ggshield.verticals.secret import Result, Results
from ggshield.verticals.secret.repo import (
    get_commits_by_batch,
    scan_commit_range,
    scan_commits_content,
)
from ggshield.verticals.secret.secret_scan_collection import SecretScanCollection
from tests.unit.conftest import _ONE_LINE_AND_MULTILINE_PATCH_CONTENT, TWO_POLICY_BREAKS


def _empty_batch_scan():
    return SecretScanCollection(id="batch", type="commit-range", scans=[])


def _commit_from_sha(sha: str) -> Commit:
    return Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )


def _client_with_one_document_per_batch() -> MagicMock:
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1
    return client


def _make_scan_progress(
    tmp_path: Path, secret_config: SecretConfig = None
) -> ScanProgress:
    secret_config = secret_config or SecretConfig()
    return ScanProgress(
        cache_path=tmp_path / "scan-progress.json",
        repository="example.com/repo",
        fingerprint=ScanProgress.build_fingerprint(
            mode=ScanMode.COMMIT_RANGE.value,
            instance="https://api.example.com",
            secret_config=secret_config,
            exclusion_regexes=set(),
        ),
        mode=ScanMode.COMMIT_RANGE.value,
        instance="https://api.example.com",
    )


def _run_commit_range(
    shas, secret_config=None, progress: ScanProgress = None, tmp_path: Path = None
):
    return scan_commit_range(
        client=_client_with_one_document_per_batch(),
        cache=MagicMock(),
        commit_list=shas,
        output_handler=MagicMock(),
        exclusion_regexes=set(),
        scan_context=ScanContext(scan_mode=ScanMode.COMMIT_RANGE, command_path="x"),
        secret_config=secret_config or SecretConfig(),
        progress=progress if progress is not None else _make_scan_progress(tmp_path),
    )


@pytest.mark.parametrize(
    "commits_sizes,batch_size,expected_batches",
    [
        (
            [1, 5, 6, 10, 2, 3, 1],
            20,
            [[1, 5, 6], [10, 2, 3, 1]],
        ),
        (
            [23, 2, 5, 6, 10, 2, 3, 1],
            20,
            [[23], [2, 5, 6], [10, 2, 3, 1]],
        ),
        (
            [1, 2, 5, 6, 10, 2, 3, 1, 23],
            20,
            [[1, 2, 5, 6], [10, 2, 3, 1], [23]],
        ),
        ([1], 20, [[1]]),
        (
            [1, 2, 5, 6, 10, 2, 3, 1, 23],
            100,
            [[1, 2, 5, 6, 10, 2, 3, 1, 23]],
        ),
        (
            [1, 2, 5, 6, 10, 2, 3, 1, 23],
            1,
            [[1], [2], [5], [6], [10], [2], [3], [1], [23]],
        ),
    ],
)
def test_get_commits_content_by_batch(
    commits_sizes: List[int],
    batch_size: int,
    expected_batches: List[List[int]],
):
    """
    GIVEN a set of commits containing a given number of files
    WHEN the number of files per commit varies
    THEN batches are still below the limit
    AND commit patches are not fully parsed (we want to delay parsing them until the
    last moment)
    """
    never_called_parser = MagicMock()

    commits = [
        Commit(
            sha=f"some_sha_{idx}",
            patch_parser=never_called_parser,
            info=CommitInformation(
                author="",
                email="",
                date="",
                paths=[Path(f"file{file_idx}") for file_idx in range(size)],
            ),
        )
        for idx, size in enumerate(commits_sizes)
    ]

    batches = list(get_commits_by_batch(commits=commits, batch_max_size=batch_size))

    never_called_parser.assert_not_called()

    for batch, expected_batch in zip(batches, expected_batches):
        assert len(batch) == len(expected_batch)
    assert len(batches) == len(expected_batches)


@patch("ggshield.verticals.secret.repo.SecretScanner")
def test_scan_2_commits_same_content(secret_scanner_mock):
    """
    GIVEN 2 commits where each commit has a file with same content and same filename
    WHEN scan_commits_content returns 2 policy break for each commit
    THEN the total number of policy breaks is 4
    """
    path = Path("filename")
    content = _ONE_LINE_AND_MULTILINE_PATCH_CONTENT
    commit_1_files = [CommitScannable("some_sha_1", path, content)]
    commit_1 = Commit(
        sha="some_sha_1",
        patch_parser=lambda commit: commit_1_files,
        info=(
            CommitInformation(
                author="",
                email="",
                date="",
                paths=[path],
            )
        ),
    )

    commit_2_files = [CommitScannable("some_sha_2", path, content)]
    commit_2 = Commit(
        sha="some_sha_2",
        patch_parser=lambda commit: commit_2_files,
        info=(
            CommitInformation(
                author="",
                email="",
                date="",
                paths=[path],
            )
        ),
    )

    secret_scanner_mock.return_value.scan.return_value = Results(
        results=[
            Result.from_scan_result(
                commit_1_files[0],
                scan_result=deepcopy(TWO_POLICY_BREAKS),
                secret_config=SecretConfig(),
            ),
            Result.from_scan_result(
                commit_2_files[0],
                scan_result=deepcopy(TWO_POLICY_BREAKS),
                secret_config=SecretConfig(),
            ),
        ],
        errors=[],
    )

    scan_collection = scan_commits_content(
        commits=[commit_1, commit_2],
        client=MagicMock(),
        cache=MagicMock(),
        scan_context=MagicMock(),
        progress_callback=(lambda advance: None),
        commit_scanned_callback=(lambda commit: None),
        secret_config=SecretConfig(),
    )

    assert len(scan_collection.scans) == 2

    all_secrets_count = sum(
        len(result.secrets) for result in scan_collection.get_all_results()
    )
    assert all_secrets_count == 4


@patch("ggshield.verticals.secret.repo.SecretScanner")
def test_scan_2_commits_file_association(secret_scanner_mock):
    """
    GIVEN 2 commits with several files in some commits
    WHEN scan_commits_content returns results with policy breaks for some of the files
    THEN the files and policy breaks are associated with the correct commits
    """
    sha1 = "some_sha_1"
    file1_1 = CommitScannable(
        sha1, Path("filename1"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document1"
    )
    file1_2 = CommitScannable(
        sha1, Path("filename2"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document2"
    )
    file1_3 = CommitScannable(
        sha1, Path("filename3"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document3"
    )
    file1_list = [file1_1, file1_2, file1_3]

    commit_1 = Commit(
        sha=sha1,
        patch_parser=lambda commit: file1_list,
        info=CommitInformation(
            author="",
            email="",
            date="",
            paths=[x.path for x in file1_list],
        ),
    )

    sha2 = "some_sha_2"
    file2_1 = CommitScannable(
        sha2, Path("filename2"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document2"
    )
    file2_2 = CommitScannable(
        sha2, Path("filename3"), _ONE_LINE_AND_MULTILINE_PATCH_CONTENT + " document3"
    )
    file2_list = [file2_1, file2_2]

    commit_2 = Commit(
        sha=sha2,
        patch_parser=lambda commit: file2_list,
        info=CommitInformation(
            author="",
            email="",
            date="",
            paths=[x.path for x in file2_list],
        ),
    )

    policy_breaks_file_1_1 = deepcopy(TWO_POLICY_BREAKS)
    policy_breaks_file_1_3 = deepcopy(TWO_POLICY_BREAKS)
    policy_breaks_file_2_1 = deepcopy(TWO_POLICY_BREAKS)
    secret_scanner_mock.return_value.scan.return_value = Results(
        results=[
            Result.from_scan_result(
                file1_3,
                scan_result=policy_breaks_file_1_3,
                secret_config=SecretConfig(),
            ),
            Result.from_scan_result(
                file2_1,
                scan_result=policy_breaks_file_2_1,
                secret_config=SecretConfig(),
            ),
            Result.from_scan_result(
                file1_1,
                scan_result=policy_breaks_file_1_1,
                secret_config=SecretConfig(),
            ),
        ],
        errors=[],
    )

    scan_collection = scan_commits_content(
        commits=[commit_1, commit_2],
        client=MagicMock(),
        cache=MagicMock(),
        scan_context=MagicMock(),
        progress_callback=(lambda advance: None),
        commit_scanned_callback=(lambda commit: None),
        secret_config=SecretConfig(),
    )

    assert len(scan_collection.scans) == 2

    # out of 3 files, only 2 results were returned
    assert sorted(
        scan_collection.scans[0].results.results, key=lambda f: f.filename
    ) == sorted(
        [
            Result.from_scan_result(
                file1_3, policy_breaks_file_1_3, secret_config=SecretConfig()
            ),
            Result.from_scan_result(
                file1_1, policy_breaks_file_1_1, secret_config=SecretConfig()
            ),
        ],
        key=lambda f: f.filename,
    )

    # out of 2 files, only 1 result was returned
    assert scan_collection.scans[1].results.results == [
        Result.from_scan_result(
            file2_1, policy_breaks_file_2_1, secret_config=SecretConfig()
        ),
    ]


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_stops_on_error(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes
):
    """
    GIVEN a range of commits, scanned one commit per batch
    WHEN scanning one of them raises
    THEN the exception propagates
    AND the remaining batches are not scanned
    """
    nb_commits = 50
    started = []

    def scan(commits, *args):
        started.append(commits)
        if len(started) == 3:
            raise RuntimeError("boom")
        time.sleep(0.05)
        return SecretScanCollection(id="batch", type="commit-range", scans=[])

    scan_commits_content_mock.side_effect = scan
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1

    with pytest.raises(RuntimeError, match="boom"):
        scan_commit_range(
            client=client,
            cache=MagicMock(),
            commit_list=[f"sha{i}" for i in range(nb_commits)],
            output_handler=MagicMock(),
            exclusion_regexes=set(),
            scan_context=ScanContext(scan_mode=ScanMode.PRE_RECEIVE, command_path="x"),
            secret_config=SecretConfig(),
        )

    assert len(started) < nb_commits


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_scans_batches_in_parallel(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes
):
    """
    GIVEN 2 batches and 2 workers
    WHEN scanning
    THEN the second batch starts before the first one ends
    """
    events = []

    def scan(commits, *args):
        events.append("start")
        time.sleep(0.1)
        events.append("end")
        return SecretScanCollection(id="batch", type="commit-range", scans=[])

    scan_commits_content_mock.side_effect = scan
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: Commit(
        sha=sha,
        patch_parser=MagicMock(),
        info=CommitInformation(author="", email="", date="", paths=[Path("f")]),
    )
    client = MagicMock()
    client.secret_scan_preferences.maximum_documents_per_scan = 1

    scan_commit_range(
        client=client,
        cache=MagicMock(),
        commit_list=["sha1", "sha2"],
        output_handler=MagicMock(),
        exclusion_regexes=set(),
        scan_context=ScanContext(scan_mode=ScanMode.PRE_RECEIVE, command_path="x"),
        secret_config=SecretConfig(),
    )

    # Sequential scanning would give ["start", "end", "start", "end"]
    assert events[:2] == ["start", "start"]


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_resumes_completed_commits(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes, tmp_path
):
    """
    GIVEN a first successful scan and a second scan of the same range with the
    same repository/scope/configuration
    WHEN resuming
    THEN previously scanned commits are not scanned again and are counted as
    resumed
    """
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: _commit_from_sha(sha)
    scan_commits_content_mock.side_effect = lambda commits, *args: _empty_batch_scan()
    shas = [f"sha{i}" for i in range(4)]

    _run_commit_range(shas, tmp_path=tmp_path)
    assert scan_commits_content_mock.call_count == 4

    reloaded = _make_scan_progress(tmp_path)
    _run_commit_range(shas, progress=reloaded)

    assert scan_commits_content_mock.call_count == 4
    assert reloaded.resumed_count == 4
    assert reloaded.retried_count == 0


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_grown_range_only_scans_new_commits(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes, tmp_path
):
    """
    GIVEN a completed scan of a range
    WHEN the same scan runs on a range grown with new commits
    THEN only the new commits are scanned
    """
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: _commit_from_sha(sha)
    scan_commits_content_mock.side_effect = lambda commits, *args: _empty_batch_scan()

    _run_commit_range(["sha1", "sha2", "sha3"], tmp_path=tmp_path)
    assert scan_commits_content_mock.call_count == 3

    reloaded = _make_scan_progress(tmp_path)
    _run_commit_range(["sha1", "sha2", "sha3", "sha4"], progress=reloaded)

    assert scan_commits_content_mock.call_count == 4
    assert reloaded.resumed_count == 3
    assert reloaded.retried_count == 0


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_config_change_rescans_everything(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes, tmp_path
):
    """
    GIVEN a completed scan under one configuration
    WHEN the same range is scanned with a different configuration
    THEN no commit is skipped using the old progress
    """
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: _commit_from_sha(sha)
    scan_commits_content_mock.side_effect = lambda commits, *args: _empty_batch_scan()
    shas = [f"sha{i}" for i in range(3)]

    _run_commit_range(shas, secret_config=SecretConfig(), tmp_path=tmp_path)
    assert scan_commits_content_mock.call_count == 3

    other_config = SecretConfig(ignored_detectors={"some_detector"})
    reloaded = _make_scan_progress(tmp_path, secret_config=other_config)
    _run_commit_range(shas, secret_config=other_config, progress=reloaded)

    assert scan_commits_content_mock.call_count == 6
    assert reloaded.resumed_count == 0


@patch("ggshield.verticals.secret.repo.MAX_WORKERS", 2)
@patch("ggshield.verticals.secret.repo.get_required_token_scopes_from_config")
@patch("ggshield.verticals.secret.repo.check_client_api_key")
@patch("ggshield.verticals.secret.repo.Commit.from_sha")
@patch("ggshield.verticals.secret.repo.scan_commits_content")
def test_scan_commit_range_retries_failed_commits_and_reports(
    scan_commits_content_mock, from_sha_mock, _check_api_key, _scopes, tmp_path, capsys
):
    """
    GIVEN a scan interrupted while scanning its 3rd batch
    WHEN the scan is resumed
    THEN the failed commit is marked failed and retried with the other missing
    commits, counted as a retry, and the end-of-scan report lists both counts
    """
    from_sha_mock.side_effect = lambda sha, exclusion_regexes: _commit_from_sha(sha)
    shas = [f"sha{i}" for i in range(5)]

    def fail_sha2_batch(commits, *args):
        if commits[0].sha == "sha2":
            raise RuntimeError("boom")
        return _empty_batch_scan()

    scan_commits_content_mock.side_effect = fail_sha2_batch

    with pytest.raises(RuntimeError, match="boom"):
        _run_commit_range(shas, tmp_path=tmp_path)

    interrupted = _make_scan_progress(tmp_path)
    assert interrupted.plan(shas) == ["sha2", "sha3", "sha4"]
    assert interrupted.scope.failed == {"sha2": "boom"}

    resumed_shas = []

    def record_resumed(commits, *args):
        resumed_shas.extend(commit.sha for commit in commits)
        return _empty_batch_scan()

    scan_commits_content_mock.side_effect = record_resumed

    reloaded = _make_scan_progress(tmp_path)
    _run_commit_range(shas, progress=reloaded)

    # Worker scheduling makes task start order non-deterministic, only the set
    # of rescanned commits is meaningful.
    assert sorted(resumed_shas) == ["sha2", "sha3", "sha4"]
    assert reloaded.resumed_count == 2
    assert reloaded.retried_count == 1
    assert reloaded.scope.failed == {}

    after = _make_scan_progress(tmp_path)
    assert after.plan(shas) == []

    err = capsys.readouterr().err
    assert "skipped 2 previously scanned commits" in err
    assert "retried 1 previously failed commit" in err
