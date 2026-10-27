import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from re import Pattern
from typing import Any, Dict, List, Optional, Set

import marshmallow_dataclass
from pygitguardian import GGClient

from ggshield.core import ui
from ggshield.core.config.user_config import SecretConfig
from ggshield.core.dirs import get_cache_dir
from ggshield.core.scan import ScanContext
from ggshield.utils.git_shell import get_git_root, get_repository_url_from_path


logger = logging.getLogger(__name__)


# Version of the on-disk file format. Bump it when the semantics of the
# stored state change: older files are then ignored instead of being used to
# skip scans.
_STATE_FILE_VERSION = 1

# Bumped when the inputs used to compute the scope fingerprint change meaning.
_FINGERPRINT_FORMAT_VERSION = 1

# Scopes (i.e. unique scan range/configuration pair) which have not been used
# for that long are dropped on load to keep the file from growing forever.
_SCOPE_RETENTION = timedelta(days=90)

_MAX_ERROR_DESCRIPTION_LENGTH = 500


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class _Scope:
    mode: str
    instance: str
    completed: Set[str] = field(default_factory=set)
    # Commit SHA -> description of the error which prevented the commit from
    # being scanned. These commits are scanned again on the next run.
    failed: Dict[str, str] = field(default_factory=dict)
    updated_at: datetime = field(default_factory=_utc_now)


def _canonicalize(value: Any) -> Any:
    """
    Make a JSON-compatible value serialization-independent, in particular sets
    and lists whose order does not matter (ignored detectors, ignored paths,
    exclusion regexes...).
    """
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if isinstance(value, (set, frozenset, tuple, list)):
        normalized = [_canonicalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value


class ScanProgress:
    """
    Remembers which commits have already been scanned for a given repository,
    scan scope and configuration, so an interrupted `secret scan repo` /
    `secret scan commit-range` run only scans the commits it is missing on the
    next run.

    The state is persisted as JSON in the user cache directory:
    `<cache dir>/scan-progress/<repository hash>.json`, one file per
    repository containing one scope per distinct (scan mode, instance, secret
    configuration, exclusion regexes) combination.

    A commit is tracked by its SHA: git commits are immutable, so a completed
    SHA can safely be skipped in later runs, including when the scan range
    grows (new SHAs are simply not recorded yet and get scanned) or shrinks
    (the intersection of the two ranges is skipped). Any change of scope or
    configuration produces a different fingerprint and therefore a fresh
    state, so old progress can never cause new content to be skipped.
    """

    def __init__(
        self,
        cache_path: Path,
        repository: str,
        fingerprint: str,
        mode: str,
        instance: str,
    ) -> None:
        self.cache_path = cache_path
        self.repository = repository
        self.fingerprint = fingerprint

        data = self._load()
        scopes = data.get("scopes", {}) if isinstance(data, dict) else {}
        self._prune_old_scopes(scopes)

        raw_scope = scopes.get(fingerprint)
        if isinstance(raw_scope, dict):
            self.scope = _Scope(
                mode=mode,
                instance=instance,
                completed=set(raw_scope.get("completed") or []),
                failed={
                    str(sha): str(description)
                    for sha, description in (raw_scope.get("failed") or {}).items()
                },
                updated_at=self._parse_timestamp(raw_scope.get("updated_at")),
            )
        else:
            self.scope = _Scope(mode=mode, instance=instance)
        self._other_scopes: Dict[str, Dict[str, Any]] = {
            key: value
            for key, value in scopes.items()
            if key != fingerprint and isinstance(value, dict)
        }

        # Filled by `plan()`, reported when the scan ends.
        self.resumed_count = 0
        self.retried_count = 0

    @staticmethod
    def build_fingerprint(
        mode: str,
        instance: str,
        secret_config: SecretConfig,
        exclusion_regexes: Set[Pattern[str]],
    ) -> str:
        # SecretConfig has no SCHEMA attribute (only UserConfig defines one),
        # build the marshmallow schema from the class directly.
        secret_config_schema = marshmallow_dataclass.class_schema(type(secret_config))()
        secret_config_dict = secret_config_schema.dump(secret_config)
        payload = _canonicalize(
            {
                "version": _FINGERPRINT_FORMAT_VERSION,
                "mode": mode,
                "instance": instance,
                "secret": secret_config_dict,
                "exclusion_regexes": [pattern.pattern for pattern in exclusion_regexes],
            }
        )
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        client: GGClient,
        scan_context: ScanContext,
        secret_config: SecretConfig,
        exclusion_regexes: Set[Pattern[str]],
    ) -> Optional["ScanProgress"]:
        """
        Build a ScanProgress for the current scan. Returns None (and displays a
        warning) if the repository cannot be identified or the cache cannot be
        used: tracking progress must never break a scan.
        """
        try:
            repository = cls._get_repository_identity(scan_context)
            if repository is None:
                return None
            scan_mode = scan_context.scan_mode
            mode = scan_mode.value if isinstance(scan_mode, Enum) else str(scan_mode)
            instance = str(getattr(client, "base_uri", "") or "")
            fingerprint = cls.build_fingerprint(
                mode=mode,
                instance=instance,
                secret_config=secret_config,
                exclusion_regexes=exclusion_regexes,
            )
            repository_hash = hashlib.sha256(repository.encode("utf-8")).hexdigest()
            cache_path = get_cache_dir() / "scan-progress" / f"{repository_hash}.json"
            return cls(
                cache_path=cache_path,
                repository=repository,
                fingerprint=fingerprint,
                mode=mode,
                instance=instance,
            )
        except Exception as exc:
            logger.warning("Failed to initialize scan progress: %s", exc)
            ui.display_warning(
                "Failed to initialize scan progress, this run cannot be resumed: "
                f"{exc}"
            )
            return None

    @staticmethod
    def _get_repository_identity(scan_context: ScanContext) -> Optional[str]:
        """
        Identify the repository being scanned. Prefer the (normalized) origin
        URL so progress is shared across clones and checkouts of the same
        repository, including the temporary mirror clone used by
        `secret scan repo <url>`. Fall back to the resolved git directory
        path for local repositories without a remote.
        """
        target_path = scan_context.target_path
        if target_path is None:
            return None
        url = get_repository_url_from_path(target_path)
        if url:
            return url
        return str(get_git_root(target_path))

    def plan(self, commit_list: List[str]) -> List[str]:
        """
        Split the commits to scan into what was already completed and what is
        still pending. Remembers the number of resumed (skipped) commits and
        retried (previously failed) commits for the end-of-scan report.
        """
        completed = self.scope.completed
        pending = [sha for sha in commit_list if sha not in completed]
        self.resumed_count = len(commit_list) - len(pending)
        self.retried_count = sum(1 for sha in pending if sha in self.scope.failed)
        return pending

    def mark_completed(self, shas: List[str]) -> None:
        if not shas:
            return
        self.scope.completed.update(shas)
        for sha in shas:
            self.scope.failed.pop(sha, None)
        self.scope.updated_at = _utc_now()
        self.save()

    def mark_failed(self, shas: List[str], description: str) -> None:
        if not shas:
            return
        truncated = description[:_MAX_ERROR_DESCRIPTION_LENGTH]
        for sha in shas:
            self.scope.failed[sha] = truncated
            # A failed commit must never be considered done, even if an older
            # state file (or an earlier batch in this run) said otherwise.
            self.scope.completed.discard(sha)
        self.scope.updated_at = _utc_now()
        self.save()

    def _load(self) -> Dict[str, Any]:
        try:
            text = self.cache_path.read_text()
            data = json.loads(text)
        except FileNotFoundError:
            return {}
        except Exception as exc:
            logger.warning(
                "Failed to load scan progress from %s: %s", self.cache_path, exc
            )
            ui.display_warning(
                f"Could not read scan progress file {self.cache_path}, "
                "starting this scan from scratch."
            )
            return {}
        if not isinstance(data, dict) or data.get("version") != _STATE_FILE_VERSION:
            return {}
        return data

    def save(self) -> None:
        data = {
            "version": _STATE_FILE_VERSION,
            "repository": self.repository,
            "scopes": {
                **self._other_scopes,
                self.fingerprint: {
                    "mode": self.scope.mode,
                    "instance": self.scope.instance,
                    "completed": sorted(self.scope.completed),
                    "failed": dict(sorted(self.scope.failed.items())),
                    "updated_at": self.scope.updated_at.isoformat(),
                },
            },
        }
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.cache_path.with_suffix(".tmp")
            # Restrict permissions: the cache directory may live in a shared
            # location and commit SHAs are still repository metadata.
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as file:
                json.dump(data, file)
            os.replace(tmp_path, self.cache_path)
        except OSError as exc:
            logger.warning(
                "Failed to save scan progress to %s: %s", self.cache_path, exc
            )

    def _prune_old_scopes(self, scopes: Dict[str, Any]) -> None:
        cutoff = _utc_now() - _SCOPE_RETENTION
        for key in list(scopes):
            raw_scope = scopes.get(key)
            if not isinstance(raw_scope, dict):
                del scopes[key]
                continue
            updated_at = self._parse_timestamp(raw_scope.get("updated_at"))
            if updated_at < cutoff:
                del scopes[key]

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                return _utc_now()
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        return _utc_now()
