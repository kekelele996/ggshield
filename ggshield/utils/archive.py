import logging
import os
import stat
import tarfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import IO, List, Optional, Tuple
from zipfile import ZipFile, ZipInfo


logger = logging.getLogger(__name__)


# Default limits enforced before an archive is unpacked. They can be overridden
# with the GG_ARCHIVE_MAX_* environment variables, see ArchiveLimits.from_env().
DEFAULT_MAX_TOTAL_SIZE = 1024**3  # 1 GiB
DEFAULT_MAX_FILE_COUNT = 10_000
DEFAULT_MAX_PATH_DEPTH = 200

_ZIP_SUFFIXES = {".zip", ".whl", ".jar"}


class UnsafeArchive(Exception):
    """
    Raised when an archive is considered unsafe.

    An archive is considered unsafe if it contains paths outside the extract directory
    or symbolic links pointing outside the extract directory.
    """

    def __init__(self):
        self.bad_paths: List[Path] = []
        self.bad_links: List[Tuple[Path, Path]] = []

    def __str__(self) -> str:
        lines: List[str] = ["Archive contains unsafe files."]
        if self.bad_paths:
            lines.append("Paths outside the archive root:")
            lines.extend(f"- {p}" for p in self.bad_paths)
        if self.bad_links:
            lines.append("Links pointing outside the archive root:")
            lines.extend(f"- {src} -> {target}" for src, target in self.bad_links)
        return "\n".join(lines)

    def add_bad_path(self, path: Path) -> None:
        self.bad_paths.append(path)

    def add_bad_link(self, path: Path, target: Path) -> None:
        self.bad_links.append((path, target))

    def has_fails(self) -> bool:
        return bool(self.bad_paths) or bool(self.bad_links)


@dataclass(frozen=True)
class ArchiveLimits:
    """
    Limits on what an archive is allowed to expand to. An archive which
    exceeds any of them is rejected before anything is written to disk.
    """

    # Maximum sum of the uncompressed sizes of the archive members, in bytes
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE
    # Maximum number of non-directory members in the archive
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    # Maximum number of path components of the deepest archive member
    max_path_depth: int = DEFAULT_MAX_PATH_DEPTH

    @staticmethod
    def _env_int(name: str, default: int) -> int:
        raw = os.getenv(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            logger.warning("Ignoring invalid %s value: %r", name, raw)
            return default
        if value <= 0:
            logger.warning("Ignoring non-positive %s value: %r", name, raw)
            return default
        return value

    @classmethod
    def from_env(cls) -> "ArchiveLimits":
        """
        Build limits from the GG_ARCHIVE_MAX_TOTAL_SIZE, GG_ARCHIVE_MAX_FILE_COUNT
        and GG_ARCHIVE_MAX_PATH_DEPTH environment variables, falling back to the
        default values when they are not set or invalid.
        """
        return cls(
            max_total_size=cls._env_int(
                "GG_ARCHIVE_MAX_TOTAL_SIZE", DEFAULT_MAX_TOTAL_SIZE
            ),
            max_file_count=cls._env_int(
                "GG_ARCHIVE_MAX_FILE_COUNT", DEFAULT_MAX_FILE_COUNT
            ),
            max_path_depth=cls._env_int(
                "GG_ARCHIVE_MAX_PATH_DEPTH", DEFAULT_MAX_PATH_DEPTH
            ),
        )


@dataclass
class ArchiveStats:
    """Information computed from the archive metadata, without extracting it."""

    total_size: int = 0
    file_count: int = 0
    max_depth: int = 0


class ArchiveLimitsExceeded(Exception):
    """
    Raised when an archive would expand beyond the configured limits.

    `violations` describes every limit which was exceeded, so the user knows
    precisely what went wrong.
    """

    def __init__(self, violations: List[str]):
        self.violations = violations

    def __str__(self) -> str:
        lines = ["Archive exceeds the safe unpacking limits:"]
        lines.extend(f"- {violation}" for violation in self.violations)
        return "\n".join(lines)


@dataclass
class UnpackReport:
    """Result of an archive unpacking."""

    stats: ArchiveStats
    # (member name, reason) pairs for members which could not be extracted.
    # Other members are still extracted: the scan is partial, not aborted.
    unread_members: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return not self.unread_members


def _format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            if unit == "B":
                return f"{size} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def _size_violation(actual: int, limit: int) -> str:
    return (
        f"total uncompressed size is {_format_size(actual)}"
        f" but the limit is {_format_size(limit)}"
    )


def _file_count_violation(actual: int, limit: int) -> str:
    return (
        f"archive contains {actual} files"
        f" but the limit is {limit} files"
    )


def _path_depth_violation(actual: int, limit: int) -> str:
    return (
        f"deepest path has {actual} components"
        f" but the limit is {limit}"
    )


def _build_limit_violations(
    stats: ArchiveStats, limits: ArchiveLimits
) -> List[str]:
    violations: List[str] = []
    if stats.total_size > limits.max_total_size:
        violations.append(_size_violation(stats.total_size, limits.max_total_size))
    if stats.file_count > limits.max_file_count:
        violations.append(
            _file_count_violation(stats.file_count, limits.max_file_count)
        )
    if stats.max_depth > limits.max_path_depth:
        violations.append(
            _path_depth_violation(stats.max_depth, limits.max_path_depth)
        )
    return violations


def _path_depth(name: str) -> int:
    """
    Return the number of meaningful components of an archive member path.

    - "foo" -> 1
    - "./subdir/foo" -> 2
    - "a/b/c" -> 3
    """
    return len(
        [part for part in PurePosixPath(name).parts if part not in ("/", ".")]
    )


def safe_unpack(
    archive: Path,
    extract_dir: Path,
    limits: Optional[ArchiveLimits] = None,
) -> UnpackReport:
    """
    If `archive` is safe and fits within `limits`, extract it in `extract_dir`.
    Otherwise, raise `UnsafeArchive` or `ArchiveLimitsExceeded` *before* writing
    anything to disk.

    Members of an otherwise valid archive which cannot be read individually are
    skipped (and reported in the returned `UnpackReport`): other members are still
    extracted, so a single bad member does not abort the whole scan.
    """
    if limits is None:
        limits = ArchiveLimits.from_env()

    stats = check_archive_content(archive, limits)

    if archive.suffix in _ZIP_SUFFIXES:
        unread_members = _unpack_zip(archive, extract_dir, limits)
    else:
        unread_members = _unpack_tar(archive, extract_dir, limits)

    return UnpackReport(stats=stats, unread_members=unread_members)


def check_archive_content(
    archive: Path, limits: Optional[ArchiveLimits] = None
) -> ArchiveStats:
    """
    Check `archive` safety and unpacking limits. Raise `UnsafeArchive` if it is
    unsafe, `ArchiveLimitsExceeded` if it would expand beyond `limits`. Return
    the archive statistics otherwise.
    """
    if limits is None:
        limits = ArchiveLimits.from_env()

    if archive.suffix in _ZIP_SUFFIXES:
        unsafe_archive, stats = _inspect_zip(archive)
    else:
        unsafe_archive, stats = _inspect_tar(archive)

    if unsafe_archive.has_fails():
        raise unsafe_archive

    violations = _build_limit_violations(stats, limits)
    if violations:
        raise ArchiveLimitsExceeded(violations)

    return stats


@lru_cache
def _archive_root():
    """
    Returns a fake archive root, used by _is_bad_path().
    Can be whatever we want except the root directory, otherwise we won't detect a path
    outside the archive root.
    """

    # The call to `resolve()` is required on Windows to include the drive letter.
    return Path("/some/dir").resolve()


def _is_bad_path(path: Path) -> bool:
    """
    Verify `path` is not outside the archive root.

    Good paths: `foo`, `foo/../bar`
    Bad paths: `../foo`, `foo/../../bar`, `/foo/bar`
    """

    root = _archive_root()

    # Use normpath for purely lexical resolution to avoid filesystem access
    # (resolve() follows symlinks on the real filesystem which can be bypassed)
    # Code can be simplified to use Path.is_relative_to() when we move to Python 3.9
    try:
        Path(os.path.normpath(root.joinpath(path))).relative_to(root)
        return False
    except ValueError:
        return True


def _is_bad_link(link: Path, target: Path) -> bool:
    """
    Given a link pointing to a target, verify it does not point outside the archive
    root.

    Good link example:
        link="foo/link", target="../file"
        Points to "file" in the archive root.

    Bad link example:
        link="foo/link", target="../../file"
        Points to "file" in the directory above the archive root.

    Another bad link example:
        link="foo/link", target="/etc/passwd"
        Points to "/etc/passwd"
    """

    # Links are interpreted relative to the directory containing them, so we join
    # target to the link parent
    target = link.parent.joinpath(target)

    return _is_bad_path(target)


def _inspect_tar(archive: Path) -> Tuple[UnsafeArchive, ArchiveStats]:
    # This exception is populated with bad paths or bad links if we find some. It's
    # only raised by check_archive_content() if we found some.
    unsafe_archive = UnsafeArchive()
    stats = ArchiveStats()

    with tarfile.open(archive) as tf:
        for info in tf:
            stats.max_depth = max(stats.max_depth, _path_depth(info.name))
            if not info.isdir():
                stats.file_count += 1
                if info.isreg():
                    stats.total_size += info.size

            path = Path(info.name)
            if _is_bad_path(path):
                unsafe_archive.add_bad_path(path)
            elif info.issym() or info.islnk():
                target = Path(info.linkname)
                if _is_bad_link(path, target):
                    unsafe_archive.add_bad_link(path, target)

    return unsafe_archive, stats


def _zip_get_symlink_target(zip: ZipFile, info: ZipInfo) -> Optional[Path]:
    """
    If `info` points to a symbolic link inside `zip`, then return the link target.
    If it's a regular file, return None.
    """
    if not stat.S_ISLNK(info.external_attr >> 16):
        return None
    target = zip.open(info).read().decode()
    return Path(target)


def _inspect_zip(archive: Path) -> Tuple[UnsafeArchive, ArchiveStats]:
    # This exception is populated with bad paths or bad links if we find some. It's
    # only raised by check_archive_content() if we found some.
    unsafe_archive = UnsafeArchive()
    stats = ArchiveStats()

    with ZipFile(archive) as zip:
        for info in zip.infolist():
            stats.max_depth = max(stats.max_depth, _path_depth(info.filename))
            if not info.is_dir():
                stats.file_count += 1
                stats.total_size += info.file_size

            path = Path(info.filename)
            if target := _zip_get_symlink_target(zip, info):
                if _is_bad_link(path, target):
                    unsafe_archive.add_bad_link(path, target)
            elif _is_bad_path(path):
                unsafe_archive.add_bad_path(path)

    return unsafe_archive, stats


def _copy_stream(
    src: IO[bytes],
    dst: IO[bytes],
    limits: "ArchiveLimits",
    total_written: int,
) -> int:
    """
    Copy src to dst in chunks, return the new number of bytes written.

    The running total is checked while copying, so a single member whose data
    is bigger than advertised (or simply bigger than the limit) is stopped
    while it is being written, instead of filling the disk first.
    """
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return total_written
        dst.write(chunk)
        total_written += len(chunk)
        if total_written > limits.max_total_size:
            raise ArchiveLimitsExceeded(
                [_size_violation(total_written, limits.max_total_size)]
            )


def _remove_partial(path: Path) -> None:
    """Remove a partially extracted member, if we created it."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
    except OSError:
        # Nothing useful we can do: the temporary directory is removed once
        # the command is done with it.
        pass


def _failure_reason(exc: Exception) -> str:
    return f"{exc.__class__.__name__}: {exc}"


def _unpack_tar(
    archive: Path,
    extract_dir: Path,
    limits: ArchiveLimits,
    total_written: int = 0,
) -> List[Tuple[str, str]]:
    """
    Extract a tar archive member by member. A member which cannot be read is
    skipped instead of aborting the whole extraction.
    """
    unread_members: List[Tuple[str, str]] = []

    with tarfile.open(archive) as tf:
        for info in tf:
            try:
                total_written = _extract_tar_member(
                    tf, info, extract_dir, limits, total_written
                )
            except ArchiveLimitsExceeded:
                # The disk budget is exhausted: do not treat this as a single
                # bad member, abort the whole extraction.
                raise
            except Exception as exc:
                # Keep going with the other members
                _remove_partial(extract_dir / info.name)
                unread_members.append((info.name, _failure_reason(exc)))

    return unread_members


def _extract_tar_member(
    tf: tarfile.TarFile,
    info: tarfile.TarInfo,
    dest: Path,
    limits: ArchiveLimits,
    total_written: int,
) -> int:
    """Extract a single tar member. Returns the new number of bytes written."""
    target = dest.joinpath(info.name)

    if info.isdir():
        target.mkdir(parents=True, exist_ok=True)
        return total_written

    target.parent.mkdir(parents=True, exist_ok=True)

    if info.issym():
        # The link target has already been validated by _inspect_tar()
        os.symlink(info.linkname, target)
        return total_written

    if info.islnk():
        # The link target has already been validated by _inspect_tar()
        os.link(dest.joinpath(info.linkname), target)
        return total_written

    if info.isreg():
        src = tf.extractfile(info)
        if src is None:
            raise OSError(f"cannot read {info.name} from archive")
        with src:
            with target.open("wb") as dst:
                # The header-declared sizes were checked up-front; the streaming
                # check still catches an archive lying about them, so a crafted
                # archive cannot fill the disk.
                return _copy_stream(src, dst, limits, total_written)

    # Other member types (devices, FIFOs...) are not scanned content: ignore them.
    return total_written


def _unpack_zip(
    archive: Path,
    extract_dir: Path,
    limits: ArchiveLimits,
    total_written: int = 0,
) -> List[Tuple[str, str]]:
    """
    Extract a zip archive member by member. A member whose data cannot be read
    (truncated data, bad CRC...) is skipped instead of aborting the whole
    extraction.
    """
    unread_members: List[Tuple[str, str]] = []

    with ZipFile(archive) as zip:
        for info in zip.infolist():
            target = extract_dir.joinpath(info.filename)
            try:
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                with zip.open(info) as src:
                    with target.open("wb") as dst:
                        # The central-directory sizes were checked up-front; the
                        # streaming check still catches an archive lying about
                        # them, so a crafted archive cannot fill the disk.
                        total_written = _copy_stream(
                            src, dst, limits, total_written
                        )
            except ArchiveLimitsExceeded:
                # The disk budget is exhausted: abort the whole extraction.
                raise
            except Exception as exc:
                # Keep going with the other members
                _remove_partial(target)
                unread_members.append((info.filename, _failure_reason(exc)))

    return unread_members
