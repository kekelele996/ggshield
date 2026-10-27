"""Tests for crash-safe group plugin-update transactions."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from ggshield.core.plugin.transaction import (
    PKG_BACKED_UP,
    STATE_COMMITTING,
    STATE_PREPARED,
    PluginTransactionError,
    PluginUpdateTransaction,
    _transaction_lock,
    recover_interrupted_transaction,
)


TRUST_STORE_NAME = "plugin_trust.json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_package(
    base: Path,
    dist: str,
    version: str,
    content: bytes,
) -> str:
    """Create a minimal on-disk plugin install; returns the wheel filename."""
    base.mkdir(parents=True, exist_ok=True)
    wheel = f"{dist.replace('-', '_')}-{version}-py3-none-any.whl"
    (base / wheel).write_bytes(content)
    manifest = {
        "plugin_name": dist,
        "version": version,
        "wheel_filename": wheel,
        "sha256": _sha(content),
    }
    (base / "manifest.json").write_text(json.dumps(manifest))
    return wheel


def _prepare_package(
    txn: PluginUpdateTransaction,
    *,
    name: str,
    dist: str,
    old_version: str,
    new_version: str,
    live_path: Path,
    content: bytes = b"",
) -> None:
    """Stage a package and register it in the journal."""
    staged_dir = txn.stage_package_dir(dist)
    wheel = _write_package(staged_dir, dist, new_version, content)
    txn.add_package(
        name=name,
        dist_name=dist,
        old_version=old_version,
        new_version=new_version,
        wheel_filename=wheel,
        sha256=_sha(content),
        live_path=live_path,
    )


def _write_trust(path: Path, plugins: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "plugins": plugins}))


def _read_manifest_version(plugin_dir: Path) -> str:
    return json.loads((plugin_dir / "manifest.json").read_text())["version"]


@pytest.fixture
def layout(tmp_path: Path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    trust = tmp_path / TRUST_STORE_NAME
    return tmp_path, plugins, trust


class TestHappyPath:
    def test_commit_switches_whole_group_and_returns_records(self, layout):
        """
        GIVEN two installed plugins and a trust document
        WHEN a transaction stages new versions for both and commits
        THEN both live directories hold the new versions, the trust document
             is replaced as one file, staging/backups are gone, and the
             returned records point at the live wheels.
        """
        root, plugins, trust = layout
        v1a, v1b = b"plugin1-v1", b"plugin2-v1"
        w1 = _write_package(plugins / "plugin1", "plugin1", "1.0.0", v1a)
        w2 = _write_package(plugins / "plugin2", "plugin2", "2.0.0", v1b)
        _write_trust(
            trust,
            {"plugin1": {"sha256": "old", "signature_status": "missing"}},
        )

        v2a, v2b = b"plugin1-v2", b"plugin2-v2"
        txn = PluginUpdateTransaction(plugins, trust)
        with txn:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=v2a,
            )
            _prepare_package(
                txn,
                name="plugin2",
                dist="plugin2",
                old_version="2.0.0",
                new_version="3.0.0",
                live_path=plugins / "plugin2",
                content=v2b,
            )
            # plugin1 is now signed (record dropped), plugin2 stays trusted.
            txn.stage_trust(
                {
                    "version": 1,
                    "plugins": {
                        "plugin2": {
                            "sha256": _sha(v2b),
                            "signature_status": "skipped",
                            "trusted_at": "now",
                        }
                    },
                }
            )
            changed = txn.commit()

        assert [p.name for p in changed] == ["plugin1", "plugin2"]
        assert changed[0].old_version == "1.0.0"
        assert changed[0].new_version == "2.0.0"
        assert changed[0].wheel_path.read_bytes() == v2a
        assert changed[1].wheel_path.read_bytes() == v2b

        assert _read_manifest_version(plugins / "plugin1") == "2.0.0"
        assert _read_manifest_version(plugins / "plugin2") == "3.0.0"
        assert not (plugins / "plugin1" / w1).exists()
        assert not (plugins / "plugin2" / w2).exists()

        trust_data = json.loads(trust.read_text())
        assert "plugin1" not in trust_data["plugins"]
        assert trust_data["plugins"]["plugin2"]["sha256"] == _sha(v2b)

        assert not (plugins / ".plugin-update").exists()

    def test_commit_with_empty_trust_removes_old_trust_file(self, layout):
        """
        GIVEN an old trust document exists but the new group is fully signed
        WHEN the transaction commits
        THEN no trust file remains.
        """
        _root, plugins, trust = layout
        _write_package(plugins / "plugin1", "plugin1", "1.0.0", b"a")
        _write_trust(trust, {"plugin1": {"sha256": "old"}})

        txn = PluginUpdateTransaction(plugins, trust)
        with txn:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=b"b",
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            txn.commit()

        assert not trust.exists()
        assert not (plugins / ".plugin-update").exists()

    def test_legacy_named_old_dir_is_moved_then_renamed(self, layout):
        """
        GIVEN the old install lives under a legacy directory name that
              differs from the wheel distribution name
        WHEN the transaction commits and is inspected
        THEN the new version lands under the distribution name and rollback
             data (had the switch failed) restores the legacy path.
        """
        _root, plugins, trust = layout
        # Old install keyed by the catalog reference, as ggshield < 1.50 did.
        _write_package(plugins / "old_catalog_name", "pkg", "1.0.0", b"old")

        txn = PluginUpdateTransaction(plugins, trust)
        with txn:
            staged = txn.stage_package_dir("pkg")
            wheel = _write_package(staged, "pkg", "2.0.0", b"new")
            txn.add_package(
                name="old_catalog_name",
                dist_name="pkg",
                old_version="1.0.0",
                new_version="2.0.0",
                wheel_filename=wheel,
                sha256=_sha(b"new"),
                live_path=plugins / "old_catalog_name",
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            changed = txn.commit()

        assert changed[0].wheel_path == plugins / "pkg" / wheel
        assert _read_manifest_version(plugins / "pkg") == "2.0.0"
        assert not (plugins / "old_catalog_name").exists()


class TestPrepareFailure:
    def test_exception_before_commit_leaves_old_group_untouched(self, layout):
        """
        GIVEN two installed plugins
        WHEN staging package 2 fails (checksum/signature/network) and the
             transaction context exits with an exception
        THEN no live directory changed, the old trust document is intact, and
             the staging area is gone.
        """
        _root, plugins, trust = layout
        old_a, old_b = b"plugin1-v1", b"plugin2-v1"
        _write_package(plugins / "plugin1", "plugin1", "1.0.0", old_a)
        _write_package(plugins / "plugin2", "plugin2", "2.0.0", old_b)
        _write_trust(trust, {"plugin2": {"sha256": _sha(old_b)}})
        trust_before = trust.read_text()

        with pytest.raises(ValueError, match="simulated prepare failure"):
            with PluginUpdateTransaction(plugins, trust) as txn:
                _prepare_package(
                    txn,
                    name="plugin1",
                    dist="plugin1",
                    old_version="1.0.0",
                    new_version="2.0.0",
                    live_path=plugins / "plugin1",
                    content=b"plugin1-v2",
                )
                raise ValueError("simulated prepare failure")

        assert (
            plugins / "plugin1" / "plugin1-1.0.0-py3-none-any.whl"
        ).read_bytes() == old_a
        assert (
            plugins / "plugin2" / "plugin2-2.0.0-py3-none-any.whl"
        ).read_bytes() == old_b
        assert _read_manifest_version(plugins / "plugin1") == "1.0.0"
        assert trust.read_text() == trust_before
        assert not (plugins / ".plugin-update").exists()

    def test_duplicate_distribution_rejected(self, layout):
        """
        GIVEN a batch already staging distribution "x"
        WHEN another package resolves to the same distribution name
        THEN staging the duplicate fails before any live mutation.
        """
        _root, plugins, trust = layout

        with PluginUpdateTransaction(plugins, trust) as txn:
            txn.stage_package_dir("dup")
            with pytest.raises(PluginTransactionError):
                txn.stage_package_dir("dup")

    def test_unexpected_live_target_aborts_prepare(self, layout):
        """
        GIVEN a live directory at the target distribution name that package
              resolution did NOT identify as this plugin's install
        WHEN add_package is called
        THEN the transaction refuses rather than destroying it.
        """
        _root, plugins, trust = layout
        _write_package(plugins / "someone-else", "someone-else", "9.0", b"x")

        with PluginUpdateTransaction(plugins, trust) as txn:
            staged = txn.stage_package_dir("someone-else")
            wheel = _write_package(staged, "someone-else", "1.0", b"y")
            with pytest.raises(PluginTransactionError):
                txn.add_package(
                    name="totally-different-plugin",
                    dist_name="someone-else",
                    old_version=None,
                    new_version="1.0",
                    wheel_filename=wheel,
                    sha256=_sha(b"y"),
                    live_path=None,
                )

        assert not (plugins / ".plugin-update").exists()
        assert _read_manifest_version(plugins / "someone-else") == "9.0"


class TestCrashRecovery:
    def _locked_txn(self, plugins: Path, trust: Path):
        """Txn with staging prepared and lock held, bypassing __enter__ recovery."""
        txn = PluginUpdateTransaction(plugins, trust)
        lock = _transaction_lock(txn.lock_path)
        lock.__enter__()
        txn.staging_root.mkdir(parents=True, exist_ok=True)
        return txn, lock

    def test_crash_after_first_swap_rolls_back_whole_group(self, layout):
        """
        GIVEN package 1 was swapped but package 2 never moved (process killed)
        WHEN a new process runs recovery
        THEN the complete old group is restored and the journal removed.
        """
        _root, plugins, trust = layout
        old_a, old_b = b"p1-old", b"p2-old"
        wheel1 = _write_package(plugins / "plugin1", "plugin1", "1.0.0", old_a)
        _write_package(plugins / "plugin2", "plugin2", "1.0.0", old_b)
        _write_trust(
            trust,
            {
                "plugin1": {"sha256": _sha(old_a), "signature_status": "missing"},
                "plugin2": {"sha256": _sha(old_b), "signature_status": "missing"},
            },
        )
        trust_before = trust.read_text()

        txn, lock = self._locked_txn(plugins, trust)
        try:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=b"p1-new",
            )
            _prepare_package(
                txn,
                name="plugin2",
                dist="plugin2",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin2",
                content=b"p2-new",
            )
            txn.stage_trust(
                {"version": 1, "plugins": {"plugin2": {"sha256": _sha(b"p2-new")}}}
            )
            txn._write_journal(STATE_COMMITTING)
            txn._commit_package(0)  # plugin1 new, plugin2 still old
            # ... process dies here, lock released by context below ...
        finally:
            lock.__exit__(None, None, None)

        outcome = recover_interrupted_transaction(plugins, trust)

        assert outcome == "rolled_back"
        assert (plugins / "plugin1" / wheel1).read_bytes() == old_a
        assert (
            plugins / "plugin2" / "plugin2-1.0.0-py3-none-any.whl"
        ).read_bytes() == old_b
        assert _read_manifest_version(plugins / "plugin1") == "1.0.0"
        assert _read_manifest_version(plugins / "plugin2") == "1.0.0"
        assert trust.read_text() == trust_before
        assert not (plugins / ".plugin-update").exists()

    def test_crash_between_backup_and_place_restores_old(self, layout):
        """
        GIVEN the old dir was moved to backup but the new dir not placed yet
        WHEN recovery runs
        THEN the old directory is moved back.
        """
        _root, plugins, trust = layout
        old = b"p1-old"
        wheel = _write_package(plugins / "plugin1", "plugin1", "1.0.0", old)

        txn, lock = self._locked_txn(plugins, trust)
        try:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=b"p1-new",
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            txn._write_journal(STATE_COMMITTING)
            package = txn.packages[0]
            Path(package["backup_path"]).parent.mkdir(parents=True, exist_ok=True)
            os.rename(package["live_path"], package["backup_path"])
            txn._checkpoint_package(0, PKG_BACKED_UP)
        finally:
            lock.__exit__(None, None, None)

        # The live dir is missing at this point — recovery must restore it.
        assert not (plugins / "plugin1").exists()

        outcome = recover_interrupted_transaction(plugins, trust)

        assert outcome == "rolled_back"
        assert (plugins / "plugin1" / wheel).read_bytes() == old
        assert not (plugins / ".plugin-update").exists()

    def test_crash_after_trust_switch_rolls_back_trust(self, layout):
        """
        GIVEN all packages were swapped and the trust document replaced but
              the journal never reached "committed"
        WHEN recovery runs
        THEN the old trust document is restored alongside the old wheels.
        """
        _root, plugins, trust = layout
        old = b"p1-old"
        _write_package(plugins / "plugin1", "plugin1", "1.0.0", old)
        _write_trust(trust, {"plugin1": {"sha256": _sha(old)}})
        trust_before = trust.read_text()

        txn, lock = self._locked_txn(plugins, trust)
        try:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=b"p1-new",
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            txn._write_journal(STATE_COMMITTING)
            txn._commit_package(0)
            txn._commit_trust()  # old trust moved to backup, no new file
        finally:
            lock.__exit__(None, None, None)

        assert not trust.exists()  # mid-switch state

        outcome = recover_interrupted_transaction(plugins, trust)

        assert outcome == "rolled_back"
        assert trust.read_text() == trust_before
        assert _read_manifest_version(plugins / "plugin1") == "1.0.0"

    def test_recovery_finishes_committed_group(self, layout):
        """
        GIVEN all renames completed (journal "committed") but cleanup (backup
              removal) did not run
        WHEN recovery runs
        THEN the new group is finalised: live new versions, backups dropped.
        """
        _root, plugins, trust = layout
        _write_package(plugins / "plugin1", "plugin1", "1.0.0", b"old1")
        _write_package(plugins / "plugin2", "plugin2", "1.0.0", b"old2")
        _write_trust(trust, {"plugin1": {"sha256": "old"}})

        txn, lock = self._locked_txn(plugins, trust)
        try:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=b"new1",
            )
            _prepare_package(
                txn,
                name="plugin2",
                dist="plugin2",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin2",
                content=b"new2",
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            for index in range(2):
                txn._commit_package(index)
            txn._commit_trust()
            txn._write_journal("committed")
            # Process dies before finish(): backups still present.
            assert txn.backup_root.exists()
        finally:
            lock.__exit__(None, None, None)

        outcome = recover_interrupted_transaction(plugins, trust)

        assert outcome == "finished"
        assert _read_manifest_version(plugins / "plugin1") == "2.0.0"
        assert _read_manifest_version(plugins / "plugin2") == "2.0.0"
        assert not (plugins / ".plugin-update").exists()
        assert not trust.exists()  # staged trust document was empty

    def test_prepared_journal_without_moves_is_rolled_back(self, layout):
        """
        GIVEN a journal published in the "prepared" state with staging only
        WHEN recovery runs
        THEN live installs are untouched and staging is discarded.
        """
        _root, plugins, trust = layout
        _write_package(plugins / "plugin1", "plugin1", "1.0.0", b"old")

        txn, lock = self._locked_txn(plugins, trust)
        try:
            _prepare_package(
                txn,
                name="plugin1",
                dist="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                live_path=plugins / "plugin1",
                content=b"new",
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            txn._write_journal(STATE_PREPARED)
        finally:
            lock.__exit__(None, None, None)

        outcome = recover_interrupted_transaction(plugins, trust)

        assert outcome == "rolled_back"
        assert _read_manifest_version(plugins / "plugin1") == "1.0.0"
        assert not (plugins / ".plugin-update").exists()

    def test_no_journal_means_nothing_to_do(self, layout):
        _root, plugins, trust = layout
        assert recover_interrupted_transaction(plugins, trust) is None


class TestCrossLayerShadow:
    def test_shadow_rollback_removes_new_copy_and_keeps_other_layer(self, tmp_path):
        """
        GIVEN the replaced copy lives in ANOTHER plugins layer (machine-wide)
              and the update only shadows it in this layer
        WHEN the switch is rolled back
        THEN only the shadowing new copy is removed; the other layer survives.
        """
        this_layer = tmp_path / "user" / "plugins"
        other_layer = tmp_path / "system" / "plugins"
        this_layer.mkdir(parents=True)
        trust = tmp_path / "plugin_trust.json"

        old = b"system-old"
        _write_package(other_layer / "plugin1", "plugin1", "1.0.0", old)

        txn = PluginUpdateTransaction(this_layer, trust)
        lock = _transaction_lock(txn.lock_path)
        lock.__enter__()
        try:
            staged = txn.stage_package_dir("plugin1")
            wheel = _write_package(staged, "plugin1", "2.0.0", b"user-new")
            txn.add_package(
                name="plugin1",
                dist_name="plugin1",
                old_version="1.0.0",
                new_version="2.0.0",
                wheel_filename=wheel,
                sha256=_sha(b"user-new"),
                live_path=other_layer / "plugin1",  # not under this_layer
            )
            txn.stage_trust({"version": 1, "plugins": {}})
            txn._write_journal(STATE_COMMITTING)
            txn._commit_package(0)
            assert (this_layer / "plugin1").exists()
            assert (other_layer / "plugin1").exists()

            txn.rollback()
        finally:
            lock.__exit__(None, None, None)

        assert not (this_layer / "plugin1").exists()
        assert (other_layer / "plugin1").exists()
        assert _read_manifest_version(other_layer / "plugin1") == "1.0.0"
        assert not (this_layer / ".plugin-update").exists()


class TestCorruptJournal:
    def test_unreadable_journal_discards_state_but_keeps_live(self, layout):
        """
        GIVEN a journal file that cannot be parsed
        WHEN recovery runs
        THEN staging/backup artifacts are removed, live plugin directories
             are left untouched, and recovery returns None (no guesswork).
        """
        _root, plugins, trust = layout
        live_wheel = _write_package(plugins / "plugin1", "plugin1", "1.0.0", b"ok")
        state = plugins / ".plugin-update"
        (state / "staging").mkdir(parents=True)
        (state / "backup").mkdir()
        (state / "transaction.json").write_text("{not json")

        outcome = recover_interrupted_transaction(plugins, trust)

        assert outcome is None
        assert (plugins / "plugin1" / live_wheel).exists()
        assert not (state / "staging").exists()
        assert not (state / "backup").exists()
        assert not (state / "transaction.json").exists()
