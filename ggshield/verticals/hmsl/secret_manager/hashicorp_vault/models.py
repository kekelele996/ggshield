from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class VaultMount:
    """
    Model to represent a Vault mount.
    """

    name: str


@dataclass
class VaultKvMount(VaultMount):
    """
    Model to represent a Vault KV mount.
    """

    version: str


@dataclass
class VaultManifestEntry:
    """
    A secret path recorded in the scan manifest, pinned to a version.

    ``version`` is the current version of the secret on a KV v2 mount at the
    time the manifest was built. It is ``None`` on KV v1 mounts, which do not
    support versioning: those entries are verified by comparing their content
    before and after fetching. It can also be ``None`` on a KV v2 mount when
    the metadata could not be read at enumeration time (for instance because
    the secret was deleted between the listing and the metadata read).
    """

    path: str
    version: Optional[int] = None


@dataclass
class VaultManifest:
    """
    Snapshot of the paths a scan will check.

    It holds the scope of the scan (``root_path`` and ``recursive``), the
    entries (paths and versions) enumerated before fetching the content and
    the paths that could not be enumerated (permission denied on a directory
    for example).
    """

    root_path: str
    recursive: bool
    entries: List[VaultManifestEntry] = field(default_factory=list)
    unreadable_paths: List[str] = field(default_factory=list)


@dataclass
class VaultScanResult:
    """
    Result of a manifest-based scan.

    - ``secrets``: the secret key/values fetched from the checked entries.
    - ``checked_paths``: entries whose content was read against a version
      that did not change while the scan was running (or after a successful
      re-read).
    - ``changed_paths``: entries that were added, deleted or modified while
      the scan was running and therefore could not be checked.
    - ``not_fetched_paths``: entries that could not be read because the token
      does not have access to them.
    """

    secrets: List[Tuple[str, str]] = field(default_factory=list)
    checked_paths: List[str] = field(default_factory=list)
    changed_paths: List[str] = field(default_factory=list)
    not_fetched_paths: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """
        True if every entry of the manifest was checked against a stable
        version. The scan can only be considered a success when this is True.
        """
        return not self.changed_paths and not self.not_fetched_paths
