"""
End-to-end tests for the group (all-or-nothing) plugin update path:

- download + checksum + signature checks land in a hidden staging area
- a failure on package N leaves packages 1..N-1 at their old versions
- trust material switches together with the wheels
- the plugin loader never sees staged artifacts and resolves a journal
  left by a killed update on startup
"""

import hashlib
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.dirs import get_plugins_dir
from ggshield.core.plugin.client import PluginDownloadInfo
from ggshield.core.plugin.downloader import (
    ChecksumMismatchError,
    PluginDownloader,
)
from ggshield.core.plugin.loader import PluginLoader
from ggshield.core.plugin.signature import (
    SignatureInfo,
    SignatureStatus,
    SignatureVerificationMode,
)


VALID_SIG = SignatureInfo(status=SignatureStatus.VALID, identity="GitGuardian/satori")
SKIPPED_SIG = SignatureInfo(status=SignatureStatus.SKIPPED)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _install_old(plugins_dir: Path, dist: str, version: str, content: bytes):
    """Create a pre-existing install under ``plugins_dir``."""
    plugin_dir = plugins_dir / dist
    plugin_dir.mkdir(parents=True, exist_ok=True)
    wheel = f"{dist.replace('-', '_')}-{version}-py3-none-any.whl"
    (plugin_dir / wheel).write_bytes(content)
    (plugin_dir / "manifest.json").write_text(
        json.dumps(
            {
                "plugin_name": dist,
                "version": version,
                "wheel_filename": wheel,
                "sha256": _sha(content),
            }
        )
    )
    return plugin_dir, wheel


def _download_info(dist: str, version: str, content: bytes) -> PluginDownloadInfo:
    return PluginDownloadInfo(
        filename=f"{dist.replace('-', '_')}-{version}-py3-none-any.whl",
        sha256=_sha(content),
        version=version,
        size_bytes=len(content),
    )


def _manifest(plugin_dir: Path) -> dict:
    return json.loads((plugin_dir / "manifest.json").read_text())


@pytest.fixture
def plugins_dir(tmp_path: Path) -> Path:
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    return plugins


class TestDownloaderGroupUpdate:
    def test_full_group_switch(self, plugins_dir):
        """
        GIVEN two installed plugins (one signed, one trusted-unsigned)
        WHEN both are staged successfully and the group commits
        THEN both live installs move to the new versions, the trust document
             reflects both decisions, staging is gone and records match.
        """
        old1, old2 = b"plugin1-v1", b"plugin2-v1"
        _install_old(plugins_dir, "plugin1", "1.0.0", old1)
        _install_old(plugins_dir, "plugin2", "2.0.0", old2)
        new1, new2 = b"plugin1-v2", b"plugin2-v2"
        info1 = _download_info("plugin1", "2.0.0", new1)
        info2 = _download_info("plugin2", "3.0.0", new2)

        with (
            patch(
                "ggshield.core.plugin.downloader.get_plugins_dir",
                return_value=plugins_dir,
            ),
            patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                side_effect=[VALID_SIG, SKIPPED_SIG],
            ),
        ):
            downloader = PluginDownloader()
            with downloader.update_transaction() as transaction:
                staged1 = downloader.stage_platform_update(
                    transaction,
                    name="plugin1",
                    old_version="1.0.0",
                    download_info=info1,
                    chunks=iter([new1]),
                )
                staged2 = downloader.stage_platform_update(
                    transaction,
                    name="plugin2",
                    old_version="2.0.0",
                    download_info=info2,
                    chunks=iter([new2]),
                    signature_mode=SignatureVerificationMode.WARN,
                )
                downloader.prepare_trust_update(transaction, [staged1, staged2])
                changed = downloader.commit_update(transaction)

        assert {p.name: p.new_version for p in changed} == {
            "plugin1": "2.0.0",
            "plugin2": "3.0.0",
        }
        assert all(p.wheel_path.exists() for p in changed)
        assert _manifest(plugins_dir / "plugin1")["version"] == "2.0.0"
        assert _manifest(plugins_dir / "plugin2")["version"] == "3.0.0"
        assert not (plugins_dir / "plugin1" / "plugin1-1.0.0-py3-none-any.whl").exists()
        assert not (plugins_dir / "plugin2" / "plugin2-2.0.0-py3-none-any.whl").exists()

        # Signed plugin: no trust exception. Unsigned plugin: exact new hash
        # trusted — the document switched with the group.
        trust = downloader.trust_store.load_data()["plugins"]
        assert "plugin1" not in trust
        assert trust["plugin2"]["sha256"] == _sha(new2)

        assert not (plugins_dir / ".plugin-update").exists()

    def test_second_package_checksum_failure_keeps_entire_old_group(self, plugins_dir):
        """
        GIVEN two installed plugins
        WHEN package 1 stages fine but package 2 fails its checksum check
        THEN the live directories AND the trust document are unchanged and
             the staging area is removed — no new/old mix on disk.
        """
        old1, old2 = b"plugin1-v1", b"plugin2-v1"
        _install_old(plugins_dir, "plugin1", "1.0.0", old1)
        _install_old(plugins_dir, "plugin2", "2.0.0", old2)

        new1 = b"plugin1-v2"
        info1 = _download_info("plugin1", "2.0.0", new1)
        info2 = PluginDownloadInfo(
            filename="plugin2-3.0.0-py3-none-any.whl",
            sha256="0" * 64,  # wrong on purpose
            version="3.0.0",
            size_bytes=99,
        )

        with (
            patch(
                "ggshield.core.plugin.downloader.get_plugins_dir",
                return_value=plugins_dir,
            ),
            patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=VALID_SIG,
            ),
        ):
            downloader = PluginDownloader()
            downloader.trust_store.trust_plugin("plugin1", _sha(old1), "missing")
            trust_before = downloader.trust_store.path.read_text()

            with pytest.raises(ChecksumMismatchError):
                with downloader.update_transaction() as transaction:
                    downloader.stage_platform_update(
                        transaction,
                        name="plugin1",
                        old_version="1.0.0",
                        download_info=info1,
                        chunks=iter([new1]),
                    )
                    downloader.stage_platform_update(
                        transaction,
                        name="plugin2",
                        old_version="2.0.0",
                        download_info=info2,
                        chunks=iter([b"actual bytes"]),
                    )

        assert (
            plugins_dir / "plugin1" / "plugin1-1.0.0-py3-none-any.whl"
        ).read_bytes() == old1
        assert (
            plugins_dir / "plugin2" / "plugin2-2.0.0-py3-none-any.whl"
        ).read_bytes() == old2
        assert _manifest(plugins_dir / "plugin1")["version"] == "1.0.0"
        assert _manifest(plugins_dir / "plugin2")["version"] == "2.0.0"
        assert downloader.trust_store.path.read_text() == trust_before
        assert not (plugins_dir / ".plugin-update").exists()

    def test_staging_is_invisible_while_preparing(self, plugins_dir):
        """
        GIVEN a transaction mid-prepare with a staged (unsigned) wheel
        WHEN the downloader resolves plugins
        THEN the staged directory is never treated as an installed plugin.
        """
        _install_old(plugins_dir, "plugin1", "1.0.0", b"old")
        new1 = b"plugin1-v2"
        info1 = _download_info("plugin1", "2.0.0", new1)

        with (
            patch(
                "ggshield.core.plugin.downloader.get_plugins_dir",
                return_value=plugins_dir,
            ),
            patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=SKIPPED_SIG,
            ),
        ):
            downloader = PluginDownloader()
            with downloader.update_transaction() as transaction:
                downloader.stage_platform_update(
                    transaction,
                    name="plugin1",
                    old_version="1.0.0",
                    download_info=info1,
                    chunks=iter([new1]),
                    signature_mode=SignatureVerificationMode.WARN,
                )

                # Staged manifest exists on disk but resolution must ignore
                # the dot-directory and keep reporting the live version.
                assert (plugins_dir / ".plugin-update" / "staging" / "plugin1").exists()
                assert downloader.get_installed_version("plugin1") == "1.0.0"

    def test_github_release_staging(self, plugins_dir):
        """
        GIVEN an update served from a GitHub release URL
        WHEN the wheel is downloaded and verified into staging and committed
        THEN the installed manifest carries github_release provenance and the
             live wheel bytes match the streamed content.
        """
        _install_old(plugins_dir, "ghplugin", "1.0.0", b"old")
        wheel_bytes = _minimal_wheel("gh_plugin", "2.0.0")
        url = (
            "https://github.com/owner/repo/releases/download/"
            "v2.0.0/gh_plugin-2.0.0-py3-none-any.whl"
        )
        response = _fake_response(url, wheel_bytes)

        def fake_get(requested_url, **kwargs):
            if requested_url == url:
                return response
            # No .sigstore sidecar published next to the release asset.
            raise requests.RequestException("no bundle")

        with (
            patch(
                "ggshield.core.plugin.downloader.get_plugins_dir",
                return_value=plugins_dir,
            ),
            patch(
                "ggshield.core.plugin.downloader.requests.get",
                side_effect=fake_get,
            ),
            patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=VALID_SIG,
            ),
        ):
            downloader = PluginDownloader()
            with downloader.update_transaction() as transaction:
                staged = downloader.stage_github_release_update(
                    transaction,
                    name="ghplugin",
                    old_version="1.0.0",
                    url=url,
                    signature_mode=SignatureVerificationMode.STRICT,
                )
                downloader.prepare_trust_update(transaction, [staged])
                changed = downloader.commit_update(transaction)

        assert changed[0].new_version == "2.0.0"
        manifest = _manifest(plugins_dir / "gh-plugin")
        assert manifest["source"]["type"] == "github_release"
        assert manifest["source"]["github_repo"] == "owner/repo"
        assert changed[0].wheel_path.read_bytes() == wheel_bytes
        assert not (plugins_dir / ".plugin-update").exists()


def _minimal_wheel(dist: str, version: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(
            f"{dist}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n",
        )
        zf.writestr(
            f"{dist}-{version}.dist-info/entry_points.txt",
            f"[ggshield.plugins]\n{dist} = {dist}.plugin:Plugin\n",
        )
    return buffer.getvalue()


def _fake_response(url: str, content: bytes):
    response = requests.models.Response()
    response.url = url
    response.status_code = 200
    response.raw = io.BytesIO(content)
    response.headers["Content-Length"] = str(len(content))

    def iter_content(chunk_size=8192):
        yield content

    response.iter_content = iter_content
    response.raise_for_status = lambda: None
    return response


class TestLoaderRecoveryAndScanning:
    def _write_live(self, plugins: Path) -> Path:
        wheel = _minimal_wheel("realplugin", "1.0.0")
        plugin_dir = plugins / "realplugin"
        plugin_dir.mkdir(parents=True)
        wheel_path = plugin_dir / "realplugin-1.0.0-py3-none-any.whl"
        wheel_path.write_bytes(wheel)
        (plugin_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "plugin_name": "realplugin",
                    "version": "1.0.0",
                    "wheel_filename": wheel_path.name,
                    "sha256": _sha(wheel),
                }
            )
        )
        return plugin_dir

    def test_scanner_ignores_dot_staging_directory(self):
        """
        GIVEN a live plugin plus a staged wheel under .plugin-update/staging
        WHEN the loader discovers local wheels
        THEN only the live plugin is reported — staged (possibly unsigned)
             wheels can never be loaded mid-update.
        """
        plugins = get_plugins_dir(create=True)
        self._write_live(plugins)

        staged_dir = plugins / ".plugin-update" / "staging" / "evilplugin"
        staged_dir.mkdir(parents=True)
        evil_wheel = staged_dir / "evilplugin-9.9.9-py3-none-any.whl"
        evil_wheel.write_bytes(_minimal_wheel("evilplugin", "9.9.9"))
        (staged_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "plugin_name": "evilplugin",
                    "version": "9.9.9",
                    "wheel_filename": evil_wheel.name,
                }
            )
        )

        loader = PluginLoader(EnterpriseConfig())
        discovered = {p.name: p for p in loader.discover_plugins()}

        assert "realplugin" in discovered
        assert "evilplugin" not in discovered

    def test_loader_construction_recovers_interrupted_update(self):
        """
        GIVEN a "prepared" journal from a killed updater and untouched lives
        WHEN PluginLoader starts
        THEN it rolls the interrupted update away before scanning.
        """
        plugins = get_plugins_dir(create=True)
        self._write_live(plugins)

        state = plugins / ".plugin-update"
        staging = state / "staging" / "realplugin"
        staging.mkdir(parents=True)
        (staging / "realplugin-2.0.0-py3-none-any.whl").write_bytes(b"new")
        journal = {
            "version": 1,
            "state": "prepared",
            "packages": [],
            "trust": {"state": "untouched"},
        }
        (state / "transaction.json").write_text(json.dumps(journal))

        loader = PluginLoader(EnterpriseConfig())
        discovered = {p.name: p for p in loader.discover_plugins()}

        assert not state.exists()
        assert discovered["realplugin"].version == "1.0.0"
        assert isinstance(loader, PluginLoader)
