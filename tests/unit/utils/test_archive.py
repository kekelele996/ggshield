import struct
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Dict, Optional
from zipfile import ZipFile

import pytest

from ggshield.utils.archive import (
    ArchiveLimits,
    ArchiveLimitsExceeded,
    UnsafeArchive,
    _unpack_tar,
    _zip_get_symlink_target,
    check_archive_content,
    safe_unpack,
)
from tests.unit.conftest import DATA_PATH


ARCHIVES_PATH = DATA_PATH / "archives"
BAD_ZIP_PATH = ARCHIVES_PATH / "bad.zip"
BAD_TAR_PATH = ARCHIVES_PATH / "bad.tar"
BAD_JAR_PATH = ARCHIVES_PATH / "bad.jar"
GOOD_ZIP_PATH = ARCHIVES_PATH / "good.zip"
GOOD_WHL_PATH = ARCHIVES_PATH / "good.whl"
GOOD_TAR_PATH = ARCHIVES_PATH / "good.tar"
GOOD_JAR_PATH = ARCHIVES_PATH / "good.jar"

"""
Both bad.zip, bad.tar, and bad.jar have the same content:

./
./fine
./subdir/
./subdir/bad-relative-symlink -> ../../bad-relative
./subdir/bad-absolute-symlink -> /tmp/bad-absolute
./subdir/fine-symlink -> ../fine
../bad-relative
/tmp/bad-absolute
"""


@pytest.mark.parametrize("archive", [BAD_ZIP_PATH, BAD_TAR_PATH, BAD_JAR_PATH])
def test_check_archive_content_raises_exception(archive: Path):
    """
    GIVEN a bad archive
    WHEN check_archive_content() is called
    THEN it raises an exception
    AND the exception contains the description of what's bad in the archive
    """
    with pytest.raises(UnsafeArchive) as exc_info:
        check_archive_content(archive)

    bad_paths = set(exc_info.value.bad_paths)
    assert bad_paths == {Path("../bad-relative"), Path("/tmp/bad-absolute")}

    bad_links = set(exc_info.value.bad_links)
    assert bad_links == {
        (Path("./subdir/bad-relative-symlink"), Path("../../bad-relative")),
        (Path("./subdir/bad-absolute-symlink"), Path("/tmp/bad-absolute")),
    }

    # Basic message check, ensures __str__() is exercised
    message = str(exc_info.value)
    assert "Paths outside the archive root:" in message
    assert "bad-relative" in message
    assert "Links pointing outside the archive root:" in message
    assert "bad-absolute-symlink" in message


@pytest.mark.parametrize(
    "archive", [GOOD_ZIP_PATH, GOOD_WHL_PATH, GOOD_TAR_PATH, GOOD_JAR_PATH]
)
def test_check_safe_unpack(tmp_path: Path, archive: Path):
    """
    GIVEN a good archive
    WHEN safe_unpack() is called
    THEN it unpacks the archive
    """
    safe_unpack(archive, tmp_path)
    unpacked_files = set(p for p in tmp_path.rglob("*") if not p.is_dir())
    assert unpacked_files == {tmp_path / "fine", tmp_path / "subdir/fine-symlink"}


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("./subdir/fine-symlink", Path("../fine")),
        ("./fine", None),
    ],
)
def test_zip_get_symlink_target(name: str, target: Optional[Path]):
    """
    GIVEN a path inside bad.zip
    WHEN asked for its symlink target
    THEN it returns the target if it's a symlink, or None if it's a regular file
    """
    with ZipFile(BAD_ZIP_PATH) as zip:
        info = zip.getinfo(name)
        assert _zip_get_symlink_target(zip, info) == target


#
# Helpers to build small archives for the limits / resilient-extraction tests
#


def _make_zip(path: Path, members: Dict[str, bytes]) -> None:
    with ZipFile(path, "w") as zip:
        for name, data in members.items():
            # ZIP_STORED (the default for writestr) keeps the member data as
            # plain bytes, which makes it possible to corrupt a single member.
            zip.writestr(name, data)


def _make_tar(path: Path, members: Dict[str, bytes], mode: str = "w") -> None:
    with tarfile.open(path, mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
            else:
                info.size = len(data)
            tf.addfile(info, BytesIO(data) if not name.endswith("/") else None)


def _add_tar_hardlink(path: Path, name: str, target: str) -> None:
    with tarfile.open(path, "a") as tf:
        info = tarfile.TarInfo(name)
        info.type = tarfile.LNKTYPE
        info.linkname = target
        tf.addfile(info)


def _corrupt_zip_member_data(path: Path, member_name: str) -> None:
    """
    Flip the first data byte of one member of a ZIP_STORED archive without
    touching its central directory, so reading the member fails its CRC check
    while the archive itself can still be opened and iterated.
    """
    raw = bytearray(path.read_bytes())
    offset = 0
    local_header_signature = b"PK\x03\x04"
    while True:
        index = raw.find(local_header_signature, offset)
        assert index != -1, f"local header for {member_name} not found"
        filename_length = struct.unpack("<H", raw[index + 26 : index + 28])[0]
        extra_length = struct.unpack("<H", raw[index + 28 : index + 30])[0]
        data_offset = index + 30 + filename_length + extra_length
        filename = raw[index + 30 : index + 30 + filename_length].decode()
        if filename == member_name:
            raw[data_offset] ^= 0xFF
            path.write_bytes(bytes(raw))
            return
        offset = index + 4


#
# Limits checked from the archive metadata
#


@pytest.mark.parametrize(
    "archive_suffix",
    [".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".whl", ".jar"],
)
def test_check_archive_content_reports_stats(
    tmp_path: Path, archive_suffix: str
):
    """
    GIVEN an archive with known members
    WHEN check_archive_content() is called with default limits
    THEN it returns the total uncompressed size, the file count and the deepest
         path depth computed from the archive metadata
    """
    archive = tmp_path / f"archive{archive_suffix}"
    members = {
        "top.txt": b"x" * 10,
        "d/": b"",
        "d/middle.txt": b"y" * 5,
        "d/e/bottom.txt": b"z" * 7,
    }
    tar_modes = {
        ".tar": "w",
        ".tar.gz": "w:gz",
        ".tar.bz2": "w:bz2",
        ".tar.xz": "w:xz",
    }
    if archive_suffix in {".zip", ".whl", ".jar"}:
        _make_zip(archive, members)
    else:
        _make_tar(archive, members, mode=tar_modes[archive_suffix])

    stats = check_archive_content(archive)

    assert stats.total_size == 22
    assert stats.file_count == 3  # directories are not counted
    assert stats.max_depth == 3


def test_check_archive_content_rejects_oversized_zip(tmp_path: Path):
    """
    GIVEN a zip archive which uncompressed content exceeds the size limit
    WHEN check_archive_content() is called
    THEN ArchiveLimitsExceeded is raised, mentioning only the size limit
    AND nothing is extracted
    """
    archive = tmp_path / "big.zip"
    _make_zip(archive, {"big.bin": b"x" * 2048})
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    with pytest.raises(ArchiveLimitsExceeded) as exc_info:
        safe_unpack(archive, extract_dir, limits=ArchiveLimits(max_total_size=1024))

    message = str(exc_info.value)
    assert "total uncompressed size is" in message
    assert "2.0 KiB" in message
    assert "limit is 1.0 KiB" in message
    assert "number of files" not in message
    assert "deepest path" not in message
    assert list(extract_dir.iterdir()) == []


@pytest.mark.parametrize("archive_suffix", [".zip", ".tar"])
def test_check_archive_content_rejects_too_many_files(
    tmp_path: Path, archive_suffix: str
):
    """
    GIVEN an archive containing more files than the file count limit
    WHEN check_archive_content() is called
    THEN ArchiveLimitsExceeded is raised, mentioning the file count
    """
    archive = tmp_path / f"many{archive_suffix}"
    members = {f"file{i}.txt": b"x" for i in range(3)}
    if archive_suffix == ".zip":
        _make_zip(archive, members)
    else:
        _make_tar(archive, members)

    with pytest.raises(ArchiveLimitsExceeded) as exc_info:
        check_archive_content(archive, limits=ArchiveLimits(max_file_count=2))

    message = str(exc_info.value)
    assert "archive contains 3 files" in message
    assert "limit is 2 files" in message
    assert "total uncompressed size" not in message


@pytest.mark.parametrize("archive_suffix", [".zip", ".tar"])
def test_check_archive_content_rejects_too_deep_paths(
    tmp_path: Path, archive_suffix: str
):
    """
    GIVEN an archive containing a path deeper than the depth limit
    WHEN check_archive_content() is called
    THEN ArchiveLimitsExceeded is raised, mentioning the path depth
    """
    archive = tmp_path / f"deep{archive_suffix}"
    members = {"a/b/c/d/too-deep.txt": b"x"}
    if archive_suffix == ".zip":
        _make_zip(archive, members)
    else:
        _make_tar(archive, members)

    with pytest.raises(ArchiveLimitsExceeded) as exc_info:
        check_archive_content(archive, limits=ArchiveLimits(max_path_depth=2))

    message = str(exc_info.value)
    assert "deepest path has 5 components" in message
    assert "limit is 2" in message


def test_check_archive_content_reports_every_exceeded_limit(tmp_path: Path):
    """
    GIVEN an archive exceeding several limits at once
    WHEN check_archive_content() is called
    THEN the error lists every exceeded limit so the user knows what to fix
    """
    archive = tmp_path / "bad.zip"
    _make_zip(archive, {f"a/b/c/file{i}.bin": b"x" * 2048 for i in range(3)})

    with pytest.raises(ArchiveLimitsExceeded) as exc_info:
        check_archive_content(
            archive,
            limits=ArchiveLimits(
                max_total_size=1024, max_file_count=2, max_path_depth=2
            ),
        )

    message = str(exc_info.value)
    assert message.count("\n") == 3  # header + 3 violations
    assert "total uncompressed size is" in message
    assert "archive contains 3 files" in message
    assert "deepest path has 4 components" in message


def test_check_archive_content_unsafe_archive_still_rejected(tmp_path: Path):
    """
    GIVEN an unsafe archive
    WHEN it is checked against limits
    THEN the unsafe check takes precedence
    """
    with pytest.raises(UnsafeArchive):
        check_archive_content(BAD_ZIP_PATH, limits=ArchiveLimits())


def test_archive_limits_from_env(monkeypatch: pytest.MonkeyPatch):
    """
    GIVEN GG_ARCHIVE_MAX_* environment variables
    WHEN ArchiveLimits.from_env() is called
    THEN it uses them, falling back to defaults for missing or invalid values
    """
    monkeypatch.setenv("GG_ARCHIVE_MAX_TOTAL_SIZE", "42")
    monkeypatch.setenv("GG_ARCHIVE_MAX_FILE_COUNT", "not-a-number")
    monkeypatch.delenv("GG_ARCHIVE_MAX_PATH_DEPTH", raising=False)

    limits = ArchiveLimits.from_env()

    assert limits.max_total_size == 42
    assert limits.max_file_count == ArchiveLimits().max_file_count
    assert limits.max_path_depth == ArchiveLimits().max_path_depth


#
# Resilient per-member extraction
#


def test_safe_unpack_zip_skips_unreadable_member(tmp_path: Path):
    """
    GIVEN a zip archive in which one member has corrupted data (bad CRC)
    WHEN safe_unpack() is called
    THEN the bad member is reported and not partially extracted
    AND the other members are still extracted
    """
    archive = tmp_path / "partial.zip"
    _make_zip(
        archive,
        {"bad.txt": b"corrupted content", "good.txt": b"healthy content"},
    )
    _corrupt_zip_member_data(archive, "bad.txt")
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    report = safe_unpack(archive, extract_dir)

    assert not report.is_complete
    assert len(report.unread_members) == 1
    member_name, reason = report.unread_members[0]
    assert member_name == "bad.txt"
    assert "crc" in reason.lower()

    # The bad member does not leave a partial file behind
    assert not (extract_dir / "bad.txt").exists()
    # The other member is extracted normally and can be read
    assert (extract_dir / "good.txt").read_bytes() == b"healthy content"


def test_safe_unpack_tar_skips_unreadable_member(tmp_path: Path):
    """
    GIVEN a tar archive in which a hardlink points to a member that was never
    stored in the archive
    WHEN safe_unpack() is called
    THEN the unreadable link is reported
    AND the regular members are still extracted
    """
    archive = tmp_path / "partial.tar"
    _make_tar(archive, {"good.txt": b"healthy content"})
    _add_tar_hardlink(archive, name="broken-link", target="missing-target")
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    report = safe_unpack(archive, extract_dir)

    assert not report.is_complete
    assert [name for name, _ in report.unread_members] == ["broken-link"]
    assert "FileNotFoundError" in report.unread_members[0][1]
    assert not (extract_dir / "broken-link").exists()
    assert (extract_dir / "good.txt").read_bytes() == b"healthy content"


def test_unpack_tar_aborts_if_actual_data_exceeds_limit(tmp_path: Path):
    """
    GIVEN an archive being streamed to disk whose actual data grows beyond the
    size limit (for example because its headers lied)
    WHEN more bytes than the limit are extracted
    THEN ArchiveLimitsExceeded is raised while extracting, not after filling
         the disk
    """
    archive = tmp_path / "big.tar"
    _make_tar(archive, {"big.bin": b"x" * 2048})
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    # Call the extraction function directly with a limit below the actual data,
    # bypassing the header-based pre-check which already rejects this archive.
    with pytest.raises(ArchiveLimitsExceeded) as exc_info:
        _unpack_tar(
            archive, extract_dir, limits=ArchiveLimits(max_total_size=1024)
        )

    assert "total uncompressed size is" in str(exc_info.value)
