"""
Atomic, crash-safe group transactions for plugin upgrades.

A single ``ggshield plugin update`` run can switch several packages at once.
Replacing them one by one is not failure-atomic: a network blip or a signature
failure on package N leaves packages 1..N-1 on the new version while N stays
on the old one, and a process killed in the middle of the switch can leave a
plugin directory holding just an unverified wheel — which the loader may pick
up on the next start.

This module implements a small write-ahead journal around the switch:

* **prepare** — every wheel and its sigstore bundle is downloaded into a
  hidden staging directory (``<plugins>/.plugin-update/staging``), checksummed
  and signature-verified by the caller, and the target manifest plus the whole
  new trust document are rendered there. The live plugin directories are
  never touched, so any failure simply discards the staging area and the
  complete old group stays in place.
* **commit** — a journal (``transaction.json``) is written first; each plugin
  directory and the trust store are then switched with same-directory
  ``rename(2)`` calls (atomic on POSIX and Windows). The journal is rewritten
  atomically after every step, so a crash at any point leaves enough
  information to restore either the complete old group or the complete new
  group — never a mix.
* **recover** — :func:`recover_interrupted_transaction` runs on startup (the
  plugin loader) and before any install/update (the downloader): a journal
  left in ``prepared``/``committing`` state rolls the complete old group
  back; a ``committed`` journal only has cleanup left and finishes the new
  group.

The state directory name starts with a dot and the wheel scanner skips
dot-directories, so staged wheels (which may be unsigned while waiting for
their trust record) can never be loaded.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional


try:  # POSIX only; replaced by a no-op lock on Windows.
    import fcntl
except ImportError:  # pragma: no cover - Windows has no fcntl
    fcntl = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)


STATE_DIR_NAME = ".plugin-update"
STAGING_DIR_NAME = "staging"
BACKUP_DIR_NAME = "backup"
JOURNAL_FILENAME = "transaction.json"
LOCK_FILENAME = "lock"
STAGED_TRUST_FILENAME = "plugin_trust.json"
BACKUP_TRUST_FILENAME = "plugin_trust.json"

JOURNAL_VERSION = 1

# Journal / package / trust lifecycle states.
STATE_PREPARED = "prepared"
STATE_COMMITTING = "committing"
STATE_COMMITTED = "committed"

PKG_PENDING = "pending"
PKG_BACKED_UP = "backed_up"
PKG_SWAPPED = "swapped"

TRUST_UNTOUCHED = "untouched"
TRUST_BACKED_UP = "backed_up"
TRUST_REPLACED = "replaced"


class PluginTransactionError(Exception):
    """A plugin group transaction could not be prepared, committed or recovered."""


@dataclass
class UpdatedPackage:
    """A package switched by a committed transaction."""

    name: str
    """Catalog / loader key the update was requested under."""

    dist_name: str
    """On-disk plugin directory (PEP 503 distribution name)."""

    old_version: Optional[str]
    new_version: str
    wheel_path: Path
    """Live wheel path after the switch."""


def _atomic_write_json(path: Path, data: Dict) -> None:
    """Write JSON to ``path`` via a same-directory temp file + rename.

    The rename is the atomic publication point: a crash can leave the old
    file or the new file, never a half-written one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    try:
        tmp_path.write_text(json.dumps(data, indent=2))
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def _read_json(path: Path) -> Optional[Dict]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _force_remove_tree(path: Path) -> None:
    """Remove a tree, fixing the usual read-only-bit blockers once.

    Mirrors ``PluginDownloader._remove_plugin_tree``: a plain
    :func:`shutil.rmtree` fails on read-only entries, so retry after a chmod
    pass. Foreign-owned trees cannot be removed; let the exception propagate
    so the caller leaves the journal in place for the next attempt instead
    of pretending the switch is finished.
    """
    try:
        shutil.rmtree(path)
        return
    except FileNotFoundError:
        return
    except OSError:
        pass

    for dirpath, _dirnames, filenames in os.walk(path):
        with contextlib.suppress(OSError):
            os.chmod(dirpath, 0o700)
        for filename in filenames:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(dirpath, filename), 0o600)
    shutil.rmtree(path)


@contextmanager
def _transaction_lock(lock_path: Path):
    """Serialise concurrent updaters on POSIX; no-op on Windows.

    ``flock`` is released by the kernel when the process dies, so a killed
    updater cannot wedge future runs waiting on a stale lock. Recovery takes
    the same lock, which means startup recovery waits for (and then observes
    the result of) an update already in progress in another process.
    """
    if fcntl is None:  # pragma: no cover - Windows path
        yield
        return

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class PluginUpdateTransaction:
    """Prepare-then-commit group update rooted at ``plugins_dir``.

    Use as a context manager::

        with PluginUpdateTransaction(plugins_dir, trust_store_path) as txn:
            staged_dir = txn.stage_package_dir("foo")
            # ... download + checksum + signature-verify into staged_dir ...
            txn.add_package(name="foo", dist_name="foo", ...)
            txn.stage_trust(trust_data)
            changed = txn.commit()

    An exception escaping the ``with`` block rolls everything back (or
    finishes a journal that already reached ``committed``) and removes the
    staging area; the live plugin directories are only ever touched inside
    :meth:`commit`.
    """

    def __init__(self, plugins_dir: Path, trust_store_path: Path) -> None:
        self.plugins_dir = Path(plugins_dir)
        self.trust_target = Path(trust_store_path)

        self.state_dir = self.plugins_dir / STATE_DIR_NAME
        self.staging_root = self.state_dir / STAGING_DIR_NAME
        self.backup_root = self.state_dir / BACKUP_DIR_NAME
        self.journal_path = self.state_dir / JOURNAL_FILENAME
        self.lock_path = self.state_dir / LOCK_FILENAME
        self.staged_trust_path = self.staging_root / STAGED_TRUST_FILENAME
        self.backup_trust_path = self.backup_root / BACKUP_TRUST_FILENAME

        self.state: Optional[str] = None
        self.packages: List[Dict] = []
        self._trust: Dict = {"state": TRUST_UNTOUCHED, "had_live": False}
        self._lock_cm: Optional[contextlib.AbstractContextManager] = None
        self._committed = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __enter__(self) -> "PluginUpdateTransaction":
        self._lock_cm = _transaction_lock(self.lock_path)
        self._lock_cm.__enter__()
        try:
            # A journal left by a killed process must be resolved before we
            # reuse the state directory. Recovery here runs while WE hold the
            # lock, so use the lock-free internal variant (taking the lock
            # again on another fd in the same thread would deadlock).
            _recover_locked(
                self.plugins_dir,
                self.trust_target,
            )
            if self.journal_path.exists():
                raise PluginTransactionError(
                    f"Another plugin update is already in progress for "
                    f"{self.plugins_dir}"
                )
            self.staging_root.mkdir(parents=True, exist_ok=True)
        except BaseException:
            self._release_lock()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if not self._committed:
                # Preparation or the switch failed (or commit was simply
                # never reached): restore the complete old group and drop all
                # staging artifacts. ``rollback`` tolerates a journal that was
                # never written (a failure during prepare); if rollback itself
                # fails the journal stays on disk so the next startup retries.
                self.rollback()
        finally:
            self._release_lock()

    def _release_lock(self) -> None:
        if self._lock_cm is not None:
            self._lock_cm.__exit__(None, None, None)
            self._lock_cm = None

    def _discard_state_dir(self) -> None:
        with contextlib.suppress(OSError):
            _force_remove_tree(self.state_dir)

    # ------------------------------------------------------------------
    # Prepare phase (no live mutation)
    # ------------------------------------------------------------------

    def stage_package_dir(self, dist_name: str) -> Path:
        """Return a fresh staging directory for one package.

        Caller fills it with the verified wheel, its sigstore bundle and the
        rendered ``manifest.json`` before calling :meth:`add_package`.
        """
        if self._committed:
            raise PluginTransactionError("Transaction already committed")
        staged_dir = self.staging_root / dist_name
        if staged_dir.exists():
            raise PluginTransactionError(
                f"Duplicate package in update batch: {dist_name!r}"
            )
        staged_dir.mkdir(parents=True, exist_ok=False)
        return staged_dir

    def add_package(
        self,
        *,
        name: str,
        dist_name: str,
        old_version: Optional[str],
        new_version: str,
        wheel_filename: str,
        sha256: str,
        live_path: Optional[Path],
    ) -> Dict:
        """Register a fully downloaded and signature-verified package.

        ``live_path`` is the directory of the version being replaced, or
        ``None`` for a brand-new install. It may carry a legacy name that
        differs from ``dist_name``; the new version is always published at
        ``plugins_dir/<dist_name>`` and a rollback restores the old
        directory at its recorded original path. A copy sitting in another
        layer (e.g. a machine-wide plugin updated by a non-root user) is
        recorded as ``in_layer=False``: the new copy shadows it rather than
        replacing it, and a rollback simply removes the shadowing copy so
        the other layer becomes visible again.
        """
        if self._committed:
            raise PluginTransactionError("Transaction already committed")

        old_live_path = Path(live_path) if live_path is not None else None
        in_layer = old_live_path is not None and self._is_relative_to(
            old_live_path, self.plugins_dir
        )
        if any(pkg["dist_name"] == dist_name for pkg in self.packages):
            raise PluginTransactionError(
                f"Duplicate package in update batch: {dist_name!r}"
            )

        # Refuse to overwrite a live directory that package resolution did
        # not identify as this plugin's install: destroying an unrelated
        # directory would violate the all-or-nothing contract. Callers can
        # resolve it by reinstalling the plugin.
        target_path = self.plugins_dir / dist_name
        if target_path.exists() and (
            old_live_path is None or target_path != old_live_path
        ):
            raise PluginTransactionError(
                f"Refusing to replace unexpected plugin directory {target_path}"
            )

        package = {
            "name": name,
            "dist_name": dist_name,
            "old_version": old_version,
            "new_version": new_version,
            "wheel_filename": wheel_filename,
            "sha256": sha256,
            "state": PKG_PENDING,
            # Where the new version is published.
            "live_path": str(target_path),
            # Where the replaced version used to live (may equal live_path,
            # carry a legacy directory name, or be absent / in another layer).
            "old_live_path": (
                str(old_live_path) if old_live_path is not None else None
            ),
            "staged_path": str(self.staging_root / dist_name),
            "backup_path": str(self.backup_root / dist_name),
            "in_layer": in_layer,
        }
        self.packages.append(package)
        return package

    def stage_trust(self, data: Dict) -> None:
        """Render the complete new trust document into staging.

        ``data`` is the full trust-store mapping (``{"version", "plugins"}``)
        with every package of this batch already applied. An empty plugin map
        is staged as "no file": replacing an old trust file with an empty one
        removes it.
        """
        if self._committed:
            raise PluginTransactionError("Transaction already committed")
        plugins = data.get("plugins") or {}
        self._trust = {
            "state": TRUST_UNTOUCHED,
            "had_live": self.trust_target.exists(),
        }
        self.staged_trust_path.parent.mkdir(parents=True, exist_ok=True)
        if self.staged_trust_path.exists():
            self.staged_trust_path.unlink()
        if plugins:
            _atomic_write_json(self.staged_trust_path, data)

    # ------------------------------------------------------------------
    # Journal
    # ------------------------------------------------------------------

    def _write_journal(self, state: str) -> None:
        self.state = state
        journal = {
            "version": JOURNAL_VERSION,
            "state": state,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "plugins_dir": str(self.plugins_dir),
            "trust_target": str(self.trust_target),
            "packages": self.packages,
            "trust": self._trust,
        }
        _atomic_write_json(self.journal_path, journal)

    def _checkpoint_package(self, index: int, state: str) -> None:
        self.packages[index]["state"] = state
        self._write_journal(STATE_COMMITTING)

    def _checkpoint_trust(self, state: str) -> None:
        self._trust["state"] = state
        self._write_journal(STATE_COMMITTING)

    # ------------------------------------------------------------------
    # Commit phase
    # ------------------------------------------------------------------

    def commit(
        self,
        publish_dir: Optional[Callable[[Path], None]] = None,
        package_finished: Optional[Callable[[Dict], None]] = None,
    ) -> List[UpdatedPackage]:
        """Switch the whole group; returns the switched package records.

        All renames are same-filesystem and individually atomic; the journal
        makes the *sequence* crash-recoverable. ``publish_dir`` (if given) is
        called on each live directory right after it appears so a root
        install can widen permissions for non-root readers;
        ``package_finished`` runs the downloader's per-package post-commit
        hooks (e.g. legacy-directory migration).
        """
        if self._committed:
            raise PluginTransactionError("Transaction already committed")
        if not self.packages:
            raise PluginTransactionError("Cannot commit an empty transaction")

        # 1. Publish the plan before touching anything live.
        self._write_journal(STATE_PREPARED)
        # 2. Open the switching window.
        self._write_journal(STATE_COMMITTING)

        # 3. One rename pair per package.
        for index, _package in enumerate(self.packages):
            self._commit_package(index, publish_dir=publish_dir)

        # 4. Trust material travels with the wheels it describes.
        self._commit_trust()

        # 5. All renames are done: from here on recovery only cleans up.
        self._write_journal(STATE_COMMITTED)
        self._committed = True

        changed = [
            UpdatedPackage(
                name=package["name"],
                dist_name=package["dist_name"],
                old_version=package["old_version"],
                new_version=package["new_version"],
                wheel_path=self.plugins_dir
                / package["dist_name"]
                / package["wheel_filename"],
            )
            for package in self.packages
        ]

        self.finish(
            publish_dir=publish_dir,
            package_finished=package_finished,
        )
        return changed

    def _commit_package(
        self,
        index: int,
        publish_dir: Optional[Callable[[Path], None]] = None,
    ) -> None:
        package = self.packages[index]
        staged_path = Path(package["staged_path"])
        # New version always lands under the distribution-name directory.
        live_path = Path(package["live_path"])
        backup_path = Path(package["backup_path"])
        old_live_path = (
            Path(package["old_live_path"]) if package.get("old_live_path") else None
        )

        live_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the live version aside (only when it lives in this layer and
        # its directory is the one the new version occupies).
        if package["in_layer"] and old_live_path is not None and old_live_path.exists():
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            os.rename(old_live_path, backup_path)
            self._checkpoint_package(index, PKG_BACKED_UP)

        # Publish the complete new directory (wheel + bundle + manifest) in
        # one atomic rename.
        os.rename(staged_path, live_path)
        self._checkpoint_package(index, PKG_SWAPPED)

        if publish_dir is not None:
            with contextlib.suppress(OSError):
                publish_dir(live_path)

    def _commit_trust(self) -> None:
        """Switch the trust document together with the group it certifies."""
        if self.trust_target.exists():
            self.backup_root.mkdir(parents=True, exist_ok=True)
            os.rename(self.trust_target, self.backup_trust_path)
            self._checkpoint_trust(TRUST_BACKED_UP)

        if self.staged_trust_path.exists():
            self.trust_target.parent.mkdir(parents=True, exist_ok=True)
            os.rename(self.staged_trust_path, self.trust_target)
        self._checkpoint_trust(TRUST_REPLACED)

    def finish(
        self,
        publish_dir: Optional[Callable[[Path], None]] = None,
        package_finished: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        """Post-commit cleanup for a ``committed`` journal.

        Widens permissions, runs the per-package ``package_finished`` hook
        (e.g. legacy-directory migration), then drops the backups and the
        whole state directory.
        """
        for package in self.packages:
            live_path = Path(package["live_path"]) if package["live_path"] else None
            if live_path is not None and live_path.exists() and publish_dir is not None:
                with contextlib.suppress(OSError):
                    publish_dir(live_path)
            if package_finished is not None:
                with contextlib.suppress(Exception):
                    package_finished(package)

        # The old group is no longer needed now that the new one is complete
        # and journaled committed.
        if self.backup_root.exists():
            _force_remove_tree(self.backup_root)
        self._discard_state_dir()

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self) -> None:
        """Restore the complete old group after an interrupted/failed switch.

        No-op (beyond dropping staging) when the journal never reached the
        switching phase. Safe to call multiple times.
        """
        journal = _read_json(self.journal_path) if self.journal_path.exists() else None
        if journal is None:
            # Failure during prepare: live dirs were never touched.
            self._discard_state_dir()
            return

        if journal.get("state") == STATE_COMMITTED:
            # Renames all completed before the crash; this is finish work,
            # not rollback work.
            self.finish()
            return

        packages = journal.get("packages") or []
        trust = journal.get("trust") or {}

        # Trust first, so a restored (possibly unsigned) wheel always finds
        # the record that authorises it.
        self._rollback_trust(trust)

        # Reverse order is not strictly required (entries are independent)
        # but keeps the sequence symmetrical with commit.
        for package in reversed(packages):
            self._rollback_package(package)

        self._discard_state_dir()
        logger.info(
            "Rolled back interrupted plugin update (%d package(s)); "
            "all plugins remain on their previous versions",
            len(packages),
        )

    def _rollback_trust(self, trust: Dict) -> None:
        state = trust.get("state", TRUST_UNTOUCHED)
        if self.backup_trust_path.exists():
            self.trust_target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(self.backup_trust_path, self.trust_target)
            return
        if state == TRUST_REPLACED and not trust.get("had_live", False):
            # A new document was published but there was no old file to
            # restore: remove the new one.
            with contextlib.suppress(FileNotFoundError):
                self.trust_target.unlink()

    def _rollback_package(self, package: Dict) -> None:
        state = package.get("state", PKG_PENDING)
        # live_path is where the new version was (or would be) published;
        # old_live_path is where the replaced version originally lived.
        live_path = Path(package["live_path"]) if package.get("live_path") else None
        old_live_path = (
            Path(package["old_live_path"]) if package.get("old_live_path") else None
        )
        backup_path = Path(package["backup_path"])

        if state == PKG_PENDING or live_path is None:
            # Nothing was moved.
            return

        restore_path = old_live_path if package.get("in_layer") else None

        if state == PKG_SWAPPED:
            if live_path.exists():
                # New version is live: remove it before restoring.
                _force_remove_tree(live_path)
            if backup_path.exists() and restore_path is not None:
                restore_path.parent.mkdir(parents=True, exist_ok=True)
                os.rename(backup_path, restore_path)
            # No backup: this entry shadowed a copy in another layer (or was
            # a fresh install); removing the new copy is the whole rollback,
            # and the other layer becomes visible again.
        elif state == PKG_BACKED_UP and restore_path is not None:
            if backup_path.exists():
                restore_path.parent.mkdir(parents=True, exist_ok=True)
                os.rename(backup_path, restore_path)

    @staticmethod
    def _is_relative_to(path: Path, other: Path) -> bool:
        try:
            Path(path).resolve().relative_to(Path(other).resolve())
            return True
        except (ValueError, OSError):
            return False


# ----------------------------------------------------------------------
# Startup recovery
# ----------------------------------------------------------------------


def _recover_locked(
    plugins_dir: Path,
    trust_store_path: Optional[Path] = None,
    publish_dir: Optional[Callable[[Path], None]] = None,
    package_finished: Optional[Callable[[Dict], None]] = None,
) -> Optional[str]:
    """Recovery logic; caller must already hold the transaction lock."""
    plugins_dir = Path(plugins_dir)
    state_dir = plugins_dir / STATE_DIR_NAME
    journal_path = state_dir / JOURNAL_FILENAME
    if not journal_path.exists():
        return None

    if trust_store_path is None:
        from ggshield.core.plugin.trust import get_trust_store_path

        trust_store_path = get_trust_store_path(plugins_dir=plugins_dir)

    journal = _read_json(journal_path)
    if journal is None:
        # Corrupt journal: do not guess which group is complete. The rename
        # protocol guarantees whatever is live is either the complete old or
        # complete new set, so drop only the staging/backup artifacts and
        # surface a warning.
        logger.warning(
            "Unreadable plugin update journal at %s; ignoring staging artifacts",
            journal_path,
        )
        for part in (STAGING_DIR_NAME, BACKUP_DIR_NAME, JOURNAL_FILENAME):
            with contextlib.suppress(OSError):
                target = state_dir / part
                if target.is_dir():
                    _force_remove_tree(target)
                else:
                    target.unlink()
        return None

    txn = PluginUpdateTransaction(plugins_dir, Path(trust_store_path))
    state = journal.get("state")
    txn.packages = journal.get("packages") or []
    txn.state = state

    if state == STATE_COMMITTED:
        txn._committed = True
        txn.finish(
            publish_dir=publish_dir,
            package_finished=package_finished,
        )
        logger.info(
            "Finalised interrupted plugin update (%d package(s))",
            len(txn.packages),
        )
        return "finished"

    # prepared / committing — or an unknown future state, which we treat
    # conservatively as "switch incomplete, restore the old group".
    txn._trust = journal.get("trust") or {"state": TRUST_UNTOUCHED}
    txn.rollback()
    return "rolled_back"


def recover_interrupted_transaction(
    plugins_dir: Path,
    trust_store_path: Optional[Path] = None,
    publish_dir: Optional[Callable[[Path], None]] = None,
    package_finished: Optional[Callable[[Dict], None]] = None,
) -> Optional[str]:
    """Resolve an interrupted update under ``plugins_dir``, if any.

    Returns ``"rolled_back"`` when an incomplete switch was undone,
    ``"finished"`` when a committed switch had its cleanup completed, or
    ``None`` when there was nothing to do. Takes the transaction lock so it
    cannot race a live updater in another process.
    """
    plugins_dir = Path(plugins_dir)
    state_dir = plugins_dir / STATE_DIR_NAME
    journal_path = state_dir / JOURNAL_FILENAME
    if not journal_path.exists():
        return None

    with _transaction_lock(state_dir / LOCK_FILENAME):
        # Re-check under the lock: another process may have finished first.
        if not journal_path.exists():
            return None
        return _recover_locked(
            plugins_dir,
            trust_store_path,
            publish_dir=publish_dir,
            package_finished=package_finished,
        )
