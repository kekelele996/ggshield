from unittest.mock import patch

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_ok


@patch("ggshield.cmd.secret.scan.range.scan_commit_range", return_value=0)
@patch("ggshield.cmd.secret.scan.range.ScanProgress")
@patch("ggshield.cmd.secret.scan.range.create_client_from_config")
@patch("ggshield.cmd.secret.scan.range.get_list_commit_SHA")
def test_commit_range_creates_and_passes_scan_progress(
    get_list_commit_SHA_mock,
    create_client_mock,
    scan_progress_mock,
    scan_commit_range_mock,
    cli_fs_runner,
):
    """
    GIVEN a `secret scan commit-range` invocation
    THEN a ScanProgress is created from the current scan configuration and
    passed to scan_commit_range, so the scan can be resumed
    """
    get_list_commit_SHA_mock.return_value = ["sha1", "sha2"]
    sentinel = object()
    scan_progress_mock.create.return_value = sentinel

    result = cli_fs_runner.invoke(cli, ["secret", "scan", "commit-range", "HEAD~2..."])

    assert_invoke_ok(result)
    scan_progress_mock.create.assert_called_once()
    assert scan_commit_range_mock.call_args.kwargs["progress"] is sentinel
