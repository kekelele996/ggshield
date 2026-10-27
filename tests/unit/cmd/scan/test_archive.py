import tempfile
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.verticals.secret import Results
from ggshield.verticals.secret.secret_scan_collection import make_file_error
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


def _make_zip(directory: Path, members: dict) -> Path:
    archive = directory / "archive.zip"
    with ZipFile(archive, "w") as zip:
        for name, data in members.items():
            zip.writestr(name, data)
    return archive


def _ggshield_temp_dirs_present() -> set:
    # TemporaryDirectory(suffix="ggshield") directories look like tmpXXXXggshield
    return {
        path
        for path in Path(tempfile.gettempdir()).glob("tmp*ggshield")
        if path.is_dir()
    }


def test_archive_cmd_rejects_archive_over_limits(cli_fs_runner, monkeypatch):
    """
    GIVEN an archive which expands beyond the configured limits
    WHEN `ggshield secret scan archive` is run
    THEN it refuses to unpack it, names the exceeded limit, exits UNEXPECTED_ERROR
    AND no unpacked content is left in the temporary directory
    """
    monkeypatch.setenv("GG_ARCHIVE_MAX_FILE_COUNT", "1")
    archive = _make_zip(Path.cwd(), {"a.txt": b"a", "b.txt": b"b"})

    before = _ggshield_temp_dirs_present()
    result = cli_fs_runner.invoke(
        cli, ["secret", "scan", "archive", str(archive)]
    )
    after = _ggshield_temp_dirs_present()

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "Refused to unpack" in result.output
    assert "exceeds the safe unpacking limits" in result.output
    assert "archive contains 2 files" in result.output
    assert after - before == set()


@patch("ggshield.cmd.secret.scan.archive.create_client_from_config")
@patch("ggshield.cmd.secret.scan.archive.SecretScanner")
def test_archive_cmd_incomplete_scan_is_distinct_from_clean(
    secret_scanner_cls, create_client, cli_fs_runner
):
    """
    GIVEN an archive which is fully unpacked but whose scan is incomplete
    WHEN `ggshield secret scan archive` is run
    THEN the exit code is SCAN_INCOMPLETE (not 0) and the output says so
    AND no temporary content is left behind
    """
    archive = _make_zip(Path.cwd(), {"a.txt": b"nothing secret here"})
    secret_scanner_cls.return_value.scan.return_value = Results(
        results=[],
        errors=[
            make_file_error(
                "corrupt.txt",
                "could not be extracted from the archive: Bad CRC-32",
            )
        ],
        incomplete=True,
    )

    before = _ggshield_temp_dirs_present()
    result = cli_fs_runner.invoke(
        cli, ["secret", "scan", "archive", str(archive)]
    )
    after = _ggshield_temp_dirs_present()

    assert_invoke_exited_with(result, ExitCode.SCAN_INCOMPLETE)
    assert "the scan is incomplete" in result.output
    assert "corrupt.txt" in result.output
    assert "some files could not be scanned" in result.output
    assert after - before == set()


@patch("ggshield.cmd.secret.scan.archive.create_client_from_config")
@patch("ggshield.cmd.secret.scan.archive.SecretScanner")
def test_archive_cmd_complete_clean_scan_is_successful(
    secret_scanner_cls, create_client, cli_fs_runner
):
    """
    GIVEN a fully scanned archive without secret
    WHEN `ggshield secret scan archive` is run
    THEN the exit code is 0 and the output says no secret was found
    """
    archive = _make_zip(Path.cwd(), {"a.txt": b"nothing secret here"})
    secret_scanner_cls.return_value.scan.return_value = Results()

    result = cli_fs_runner.invoke(
        cli, ["secret", "scan", "archive", str(archive)]
    )

    assert_invoke_ok(result)
    assert "No secrets have been found" in result.output
    assert "incomplete" not in result.output
