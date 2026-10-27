import hashlib
import json
import logging
from enum import Enum
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultAPIError,
    VaultForbiddenItemError,
    VaultInvalidUrlError,
    VaultNotFoundItemError,
    VaultPathIsNotADirectoryError,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultManifest,
    VaultManifestEntry,
    VaultScanResult,
)


logger = logging.getLogger(__name__)


class VaultEntryStatus(str, Enum):
    """Final status of a manifest entry once the scan is complete."""

    # The entry was fetched against a version that did not change during the scan
    CHECKED = "checked"
    # The entry was added, deleted or modified while the scan was running
    CHANGED = "changed"
    # The entry could not be read because the token does not have access to it
    UNREADABLE = "unreadable"


class VaultAPIClient:
    """Client to interact with Vault API."""

    def __init__(self, vault_url: str, api_token: str) -> None:
        self.session = requests.Session()
        self.session.headers["X-Vault-Token"] = api_token

        if not vault_url.startswith("http://") and not vault_url.startswith("https://"):
            vault_url = f"https://{vault_url}"
        try:
            self.vault_url = urlparse(vault_url).geturl()
        except ValueError:
            raise VaultInvalidUrlError(
                f"cannot parse the Vault URL '{vault_url}'. Are you sure it is valid?"
            )

    _DEFAULT_TIMEOUT = 30
    # Number of times an entry is re-read after a change is detected before
    # being marked as changed/unchecked.
    _MAX_REREAD_ATTEMPTS = 1

    def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        api_version: str = "v1",
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make request to the API.
        """
        try:
            api_res = self.session.request(
                method,
                f"{self.vault_url}/{api_version}/{endpoint}",
                timeout=self._DEFAULT_TIMEOUT,
                params=params,
            )
        except requests.exceptions.RequestException as e:
            raise VaultAPIError(f"Network error contacting Vault: {e}") from e
        api_res.raise_for_status()

        return api_res.json()

    def get_kv_mounts(self) -> Generator[VaultKvMount, None, None]:
        """
        Get all kv mounts for the Vault instance.

        Will try the /sys/mounts endpoint first, and if there is a forbidden error
        fallback to the /sys/internal/ui internal endpoint.
        """

        try:
            api_res = self._make_request("sys/mounts")["data"]
        except requests.HTTPError:
            api_res = self._make_request("sys/internal/ui/mounts")["data"]["secret"]

        for key, value in api_res.items():
            if value["type"] != "kv":
                continue

            yield VaultKvMount(
                name=key.rstrip("/"),  # remove trailing slash
                version=value["options"]["version"],
            )

    def list_kv_items(self, mount: VaultKvMount, path: str) -> List[str]:
        logger.debug(f"Listing kv items for mount {mount.name} at {path}")

        # Strip leading slash so the endpoint stays canonical: recent Vault versions
        # reject non-canonical "//" paths with a 400 instead of redirecting them.
        path = path.lstrip("/")
        api_endpoint = (
            f"{mount.name}/metadata/{path}"
            if mount.version == "2"
            else f"{mount.name}/{path}"
        )

        try:
            api_res = self._make_request(api_endpoint, method="LIST")
        except requests.HTTPError as exc:
            response = exc.response
            if response is not None:
                if response.status_code == 403:
                    raise VaultForbiddenItemError(
                        f"cannot access item on mount {mount.name} at path {path}"
                    )

                # The API return 404 when trying to list items when the path is a file
                # and not a directory
                if response.status_code == 404:
                    raise VaultPathIsNotADirectoryError()

            raise exc

        return [item.rstrip("/") for item in api_res["data"]["keys"]]

    def _get_kv_secrets_raw(
        self,
        mount: VaultKvMount,
        path: str,
        version: Optional[int] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Get the raw secret data and metadata from the specified mount at the
        specified path.

        On a KV v2 mount, ``version`` can be provided to fetch a specific
        version of the secret instead of the current one.

        Returns a tuple containing the secret data (a dict mapping secret
        names to their values) and the version metadata (an empty dict for
        KV v1 mounts).
        """

        logger.debug(f"Getting secrets at {path}")
        params = (
            {"version": version}
            if mount.version == "2" and version is not None
            else None
        )
        api_endpoint = (
            f"{mount.name}/data/{path}"
            if mount.version == "2"
            else f"{mount.name}/{path}"
        )
        try:
            api_res = self._make_request(api_endpoint, params=params)
        except requests.HTTPError as exc:
            response = exc.response
            if response is not None:
                if response.status_code == 403:
                    raise VaultForbiddenItemError(
                        f"cannot access item on mount {mount.name} at path {path}"
                    )

                if response.status_code == 404:
                    raise VaultNotFoundItemError(
                        f"{path} was not found: it's either not a file, "
                        "was deleted or cannot be accessed with the current token"
                    )

            raise exc

        if mount.version == "2":
            return api_res["data"]["data"], api_res["data"]["metadata"]
        return api_res["data"], {}

    def get_kv_secrets(
        self, mount: VaultKvMount, path: str, version: Optional[int] = None
    ) -> List[Tuple[str, str]]:
        """
        Get secrets from the specified mount at the specified path.

        On a KV v2 mount, ``version`` can be provided to fetch a specific
        version of the secret.

        Returns a list of tuples containing secret key and secret value
        """

        data, _ = self._get_kv_secrets_raw(mount, path, version)
        return [
            (f"{path}/{secret_name}", secret_value)
            for secret_name, secret_value in data.items()
        ]

    def get_current_kv_version(self, mount: VaultKvMount, path: str) -> Optional[int]:
        """
        Get the current version of a secret.

        Returns the version number on a KV v2 mount. KV v1 mounts do not
        support versioning, so ``None`` is returned without making any call.
        """

        if mount.version != "2":
            return None

        logger.debug(f"Getting current version for {path}")
        api_endpoint = f"{mount.name}/metadata/{path.lstrip('/')}"
        try:
            api_res = self._make_request(api_endpoint)
        except requests.HTTPError as exc:
            response = exc.response
            if response is not None:
                if response.status_code == 403:
                    raise VaultForbiddenItemError(
                        f"cannot access item on mount {mount.name} at path {path}"
                    )

                if response.status_code == 404:
                    raise VaultNotFoundItemError(
                        f"{path} was not found: it's either not a file, "
                        "was deleted or cannot be accessed with the current token"
                    )

            raise exc

        return api_res["data"]["current_version"]

    #
    # Manifest building
    #

    @staticmethod
    def _join_path(path: str, item: str) -> str:
        return f"{path}/{item}".lstrip("/")

    def _add_manifest_entry(
        self,
        mount: VaultKvMount,
        file_path: str,
        entries: List[VaultManifestEntry],
        unreadable_paths: List[str],
    ) -> None:
        """
        Add a file path to the manifest, recording its current version on
        KV v2 mounts. If the metadata cannot be read, the path is recorded as
        unreadable instead.
        """
        try:
            version = self.get_current_kv_version(mount, file_path)
        except VaultForbiddenItemError as exc:
            logger.debug(f"Forbidden error: {exc}")
            unreadable_paths.append(file_path)
            return
        except VaultNotFoundItemError as exc:
            # The file was listed but its metadata cannot be read anymore:
            # it was deleted between the listing and the metadata read.
            # Record it without a version, the fetch step will classify it.
            logger.debug(f"Not found error: {exc}")
            version = None

        entries.append(VaultManifestEntry(path=file_path, version=version))

    def _walk_manifest(
        self,
        mount: VaultKvMount,
        folder_path: str,
        recursive: bool,
        entries: List[VaultManifestEntry],
        unreadable_paths: List[str],
    ) -> None:
        """
        Walk the given folder path and fill the manifest with the file
        entries and the unreadable paths found along the way.
        """
        try:
            subitems = self.list_kv_items(mount, folder_path)
        except VaultPathIsNotADirectoryError:
            self._add_manifest_entry(mount, folder_path, entries, unreadable_paths)
            return
        except VaultForbiddenItemError as exc:
            logger.debug(f"Forbidden error: {exc}")
            unreadable_paths.append(folder_path)
            return

        if not recursive:
            return

        for item in subitems:
            self._walk_manifest(
                mount,
                self._join_path(folder_path, item),
                True,
                entries,
                unreadable_paths,
            )

    def build_manifest(
        self, mount: VaultKvMount, path: str, recursive: bool
    ) -> VaultManifest:
        """
        Enumerate all the secret paths to check under the given path and
        record the version of each one, without fetching their content yet.

        Paths that cannot be enumerated (a directory the token cannot list
        for example) end up in ``unreadable_paths``.
        """
        entries: List[VaultManifestEntry] = []
        unreadable_paths: List[str] = []

        try:
            keys = self.list_kv_items(mount, path)
        except VaultPathIsNotADirectoryError:
            # The given path is a file, the manifest only contains it.
            self._add_manifest_entry(mount, path.strip("/"), entries, unreadable_paths)
            return self._build_manifest_result(
                path, recursive, entries, unreadable_paths
            )

        # The given path is a folder: walk each of its items.
        for key in keys:
            self._walk_manifest(
                mount,
                self._join_path(path, key),
                recursive,
                entries,
                unreadable_paths,
            )

        return self._build_manifest_result(path, recursive, entries, unreadable_paths)

    def _build_manifest_result(
        self,
        path: str,
        recursive: bool,
        entries: List[VaultManifestEntry],
        unreadable_paths: List[str],
    ) -> VaultManifest:
        return VaultManifest(
            root_path=path.strip("/"),
            recursive=recursive,
            entries=sorted(entries, key=lambda entry: entry.path),
            unreadable_paths=sorted(set(unreadable_paths)),
        )

    #
    # Manifest fetching and verification
    #

    @staticmethod
    def _fingerprint(secrets: List[Tuple[str, str]]) -> str:
        """
        Compute a stable fingerprint of a secret list, used to detect
        changes on KV v1 mounts which have no version numbers.
        """
        serialized = json.dumps(
            secrets, sort_keys=True, separators=(",", ":"), default=str
        )
        return hashlib.sha256(serialized.encode()).hexdigest()

    def _fetch_v2_entry(
        self, mount: VaultKvMount, entry: VaultManifestEntry
    ) -> Tuple[VaultEntryStatus, List[Tuple[str, str]]]:
        """
        Fetch a KV v2 entry pinned to its manifest version, and verify the
        current version did not move while scanning.

        If the version moved, re-read the newest version once: the entry is
        checked only if the second read is also stable.
        """
        version: Optional[int] = entry.version

        for _ in range(self._MAX_REREAD_ATTEMPTS + 1):
            try:
                secrets, metadata = self._get_kv_secrets_raw(mount, entry.path, version)
                current_version = self.get_current_kv_version(mount, entry.path)
            except VaultForbiddenItemError as exc:
                logger.debug(f"Forbidden error: {exc}")
                return VaultEntryStatus.UNREADABLE, []
            except VaultNotFoundItemError as exc:
                # The pinned version (or the whole secret) was deleted
                logger.debug(f"Not found error: {exc}")
                return VaultEntryStatus.CHANGED, []

            fetched_version = metadata.get("version")
            if (
                current_version is not None
                and fetched_version is not None
                and current_version == fetched_version
            ):
                return VaultEntryStatus.CHECKED, [
                    (f"{entry.path}/{name}", value) for name, value in secrets.items()
                ]

            # The secret was updated during the scan: re-read the newest
            # version and verify it again.
            logger.debug(
                f"{entry.path} changed during the scan "
                f"(fetched version {fetched_version}, current {current_version})"
            )
            version = current_version

        return VaultEntryStatus.CHANGED, []

    def _fetch_v1_entry(
        self, mount: VaultKvMount, entry: VaultManifestEntry
    ) -> Tuple[VaultEntryStatus, List[Tuple[str, str]]]:
        """
        Fetch a KV v1 entry.

        KV v1 has no versioning, so the content is read twice: the entry is
        checked only if both reads return the same content. If they differ,
        the content is re-read once more and the entry is checked only if
        this last read is identical to the previous one.
        """
        try:
            previous_secrets = self.get_kv_secrets(mount, entry.path)
        except VaultForbiddenItemError as exc:
            logger.debug(f"Forbidden error: {exc}")
            return VaultEntryStatus.UNREADABLE, []
        except VaultNotFoundItemError as exc:
            logger.debug(f"Not found error: {exc}")
            return VaultEntryStatus.CHANGED, []

        for _ in range(self._MAX_REREAD_ATTEMPTS + 1):
            try:
                current_secrets = self.get_kv_secrets(mount, entry.path)
            except VaultForbiddenItemError as exc:
                logger.debug(f"Forbidden error: {exc}")
                return VaultEntryStatus.UNREADABLE, []
            except VaultNotFoundItemError as exc:
                logger.debug(f"Not found error: {exc}")
                return VaultEntryStatus.CHANGED, []

            if self._fingerprint(previous_secrets) == self._fingerprint(
                current_secrets
            ):
                return VaultEntryStatus.CHECKED, current_secrets

            # The content changed during the scan: re-read once and compare
            # the new content again.
            previous_secrets = current_secrets

        return VaultEntryStatus.CHANGED, []

    def _fetch_entry(
        self, mount: VaultKvMount, entry: VaultManifestEntry
    ) -> Tuple[VaultEntryStatus, List[Tuple[str, str]]]:
        if mount.version == "2":
            return self._fetch_v2_entry(mount, entry)
        return self._fetch_v1_entry(mount, entry)

    def scan_manifest(
        self, mount: VaultKvMount, manifest: VaultManifest
    ) -> VaultScanResult:
        """
        Fetch and verify every entry of a manifest.

        Once all entries have been fetched, the scope of the scan is
        enumerated a second time to detect secrets that were added or
        deleted while the scan was running.

        The returned result separates checked entries, entries that changed
        during the scan and unreadable entries. It is complete (and the
        scan can be considered a success) only if the two last buckets are
        empty.
        """
        checked_paths: Set[str] = set()
        changed_paths: Set[str] = set()
        unreadable_paths: Set[str] = set(manifest.unreadable_paths)
        secrets: List[Tuple[str, str]] = []

        def classify(
            status: VaultEntryStatus,
            path: str,
            entry_secrets: List[Tuple[str, str]],
        ) -> None:
            if status == VaultEntryStatus.CHECKED:
                checked_paths.add(path)
                unreadable_paths.discard(path)
                changed_paths.discard(path)
                secrets.extend(entry_secrets)
            elif status == VaultEntryStatus.CHANGED:
                checked_paths.discard(path)
                unreadable_paths.discard(path)
                changed_paths.add(path)
            else:
                if path not in changed_paths:
                    checked_paths.discard(path)
                    unreadable_paths.add(path)

        # Phase 1: fetch every manifest entry, pinned to its recorded version.
        for entry in manifest.entries:
            status, entry_secrets = self._fetch_entry(mount, entry)
            classify(status, entry.path, entry_secrets)

        # Phase 2: re-enumerate the scope to reconcile the manifest with the
        # current state of the Vault.
        final_manifest = self.build_manifest(
            mount, manifest.root_path, manifest.recursive
        )

        for path in final_manifest.unreadable_paths:
            if path not in changed_paths and path not in checked_paths:
                unreadable_paths.add(path)

        initial_paths = {entry.path for entry in manifest.entries}
        final_paths = {entry.path for entry in final_manifest.entries}

        # Entries that disappeared from the Vault were deleted during the scan.
        for path in initial_paths - final_paths:
            classify(VaultEntryStatus.CHANGED, path, [])

        # Entries that appeared during the scan are fetched and verified like
        # the others: they are checked if their version is stable.
        for entry in final_manifest.entries:
            if entry.path in initial_paths:
                continue
            status, entry_secrets = self._fetch_entry(mount, entry)
            classify(status, entry.path, entry_secrets)

        # Drop secrets belonging to paths that ended up reclassified (for
        # example checked first but deleted before the final enumeration).
        valid_prefixes = tuple(f"{path}/" for path in checked_paths)
        secrets = [secret for secret in secrets if secret[0].startswith(valid_prefixes)]

        return VaultScanResult(
            secrets=sorted(secrets),
            checked_paths=sorted(checked_paths),
            changed_paths=sorted(changed_paths),
            not_fetched_paths=sorted(unreadable_paths),
        )

    def get_secrets(
        self, mount: VaultKvMount, path: str, recursive: bool
    ) -> VaultScanResult:
        """
        Build a manifest of the secrets under the given path and scan it.
        See ``build_manifest`` and ``scan_manifest`` for details.
        """
        manifest = self.build_manifest(mount, path, recursive)
        return self.scan_manifest(mount, manifest)
