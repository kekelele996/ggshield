import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.scan_progress import ScanProgress
from ggshield.core.types import IgnoredMatch


def _make_progress(
    tmp_path: Path,
    fingerprint: str = "fingerprint-1",
    cache_name: str = "repo.json",
) -> ScanProgress:
    return ScanProgress(
        cache_path=tmp_path / cache_name,
        repository="example.com/my/repo",
        fingerprint=fingerprint,
        mode=ScanMode.COMMIT_RANGE.value,
        instance="https://api.example.com",
    )


def test_fingerprint_is_stable():
    """
    GIVEN identical scope parameters
    WHEN computing the fingerprint twice, including sets given in different
    iteration orders
    THEN the fingerprint is identical
    """
    regexes = {re.compile("a"), re.compile("b")}
    config = SecretConfig(ignored_detectors={"detector_a", "detector_b"})

    fingerprint_1 = ScanProgress.build_fingerprint(
        mode="commit_range",
        instance="https://api.example.com",
        secret_config=config,
        exclusion_regexes=regexes,
    )
    fingerprint_2 = ScanProgress.build_fingerprint(
        mode="commit_range",
        instance="https://api.example.com",
        secret_config=config,
        exclusion_regexes=set(reversed(list(regexes))),
    )

    assert fingerprint_1 == fingerprint_2


def test_fingerprint_changes_when_scope_or_config_changes():
    """
    GIVEN a fingerprint for a scope
    WHEN the scan mode, the instance, the secret config or the exclusion
    regexes change
    THEN the fingerprint is different, so old progress cannot skip content
    scanned under another scope/configuration
    """
    config = SecretConfig()
    kwargs = dict(
        mode="commit_range",
        instance="https://api.example.com",
        secret_config=config,
        exclusion_regexes=set(),
    )
    base = ScanProgress.build_fingerprint(**kwargs)

    assert (
        ScanProgress.build_fingerprint(**{**kwargs, "mode": ScanMode.REPO.value})
        != base
    )
    assert (
        ScanProgress.build_fingerprint(
            **{**kwargs, "instance": "https://other.api.example.com"}
        )
        != base
    )
    assert (
        ScanProgress.build_fingerprint(
            **{
                **kwargs,
                "secret_config": SecretConfig(
                    ignored_matches=[IgnoredMatch(match="some-secret")]
                ),
            }
        )
        != base
    )
    assert (
        ScanProgress.build_fingerprint(
            **{**kwargs, "exclusion_regexes": {re.compile("vendor/.*")}}
        )
        != base
    )


def test_plan_splits_pending_resumed_and_retried(tmp_path):
    """
    GIVEN a state with completed and failed commits
    WHEN planning a range
    THEN only pending commits are returned, and resumed/retried counters are
    computed
    """
    cache_path = tmp_path / "repo.json"
    cache_path.write_text(
        json.dumps(
            {
                "version": 1,
                "repository": "example.com/my/repo",
                "scopes": {
                    "fingerprint-1": {
                        "mode": "commit_range",
                        "instance": "https://api.example.com",
                        "completed": ["sha1", "sha2"],
                        "failed": {"sha3": "RuntimeError: boom"},
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                },
            }
        )
    )

    progress = _make_progress(tmp_path)
    pending = progress.plan(["sha1", "sha2", "sha3", "sha4"])

    assert pending == ["sha3", "sha4"]
    assert progress.resumed_count == 2
    assert progress.retried_count == 1


def test_plan_on_grown_range_only_keeps_new_commits_pending(tmp_path):
    """
    GIVEN commits already scanned
    WHEN the range grows with new commits
    THEN the new commits are pending and the old ones are resumed, new content
    is never skipped through stale progress
    """
    progress = _make_progress(tmp_path)
    progress.plan(["sha1", "sha2"])
    progress.mark_completed(["sha1", "sha2"])

    progress = _make_progress(tmp_path)
    pending = progress.plan(["sha1", "sha2", "sha3"])

    assert pending == ["sha3"]
    assert progress.resumed_count == 2
    assert progress.retried_count == 0


def test_mark_completed_persists_across_instances(tmp_path):
    """
    GIVEN a fresh progress state
    WHEN commits are marked completed
    THEN a new instance loading the same file sees them as completed
    """
    progress = _make_progress(tmp_path)
    assert progress.plan(["sha1", "sha2"]) == ["sha1", "sha2"]

    progress.mark_completed(["sha1"])
    progress.mark_completed(["sha2"])

    reloaded = _make_progress(tmp_path)
    assert reloaded.plan(["sha1", "sha2"]) == []
    assert reloaded.resumed_count == 2


def test_successful_retry_clears_failed_state(tmp_path):
    """
    GIVEN a commit previously marked as failed
    WHEN it is retried and succeeds
    THEN it moves from failed to completed
    """
    progress = _make_progress(tmp_path)
    progress.mark_failed(["sha1"], "RuntimeError: boom")
    assert progress.plan(["sha1"]) == ["sha1"]
    assert progress.retried_count == 1

    progress.mark_completed(["sha1"])

    reloaded = _make_progress(tmp_path)
    assert reloaded.scope.failed == {}
    assert reloaded.plan(["sha1"]) == []
    assert reloaded.retried_count == 0
    assert reloaded.resumed_count == 1


def test_scopes_with_different_fingerprints_are_isolated(tmp_path):
    """
    GIVEN progress under one configuration
    WHEN loading the same repository file with another fingerprint
    THEN no commit is considered completed, but the other scope is preserved
    on disk
    """
    progress = _make_progress(tmp_path, fingerprint="fp-a")
    progress.mark_completed(["sha1"])

    other = _make_progress(tmp_path, fingerprint="fp-b")
    assert other.plan(["sha1"]) == ["sha1"]
    other.mark_completed(["sha2"])

    data = json.loads((tmp_path / "repo.json").read_text())
    assert set(data["scopes"]) == {"fp-a", "fp-b"}
    assert data["scopes"]["fp-a"]["completed"] == ["sha1"]
    assert data["scopes"]["fp-b"]["completed"] == ["sha2"]


def test_corrupt_file_starts_fresh_without_raising(tmp_path):
    """
    GIVEN a progress file containing invalid JSON
    WHEN loading it
    THEN no exception is raised and the scan starts from scratch
    """
    cache_path = tmp_path / "repo.json"
    cache_path.write_text("not json")

    progress = _make_progress(tmp_path)
    assert progress.plan(["sha1"]) == ["sha1"]

    progress.mark_completed(["sha1"])
    assert json.loads(cache_path.read_text())["scopes"]


def test_unknown_file_version_is_ignored(tmp_path):
    """
    GIVEN a state file written by a newer/older incompatible version
    WHEN loading it
    THEN it is ignored
    """
    (tmp_path / "repo.json").write_text(
        json.dumps({"version": 999, "scopes": {"fingerprint-1": {}}})
    )

    progress = _make_progress(tmp_path)
    assert progress.scope.completed == set()


def test_old_scopes_are_pruned(tmp_path):
    """
    GIVEN scopes which have not been touched for longer than the retention
    WHEN loading the file
    THEN the stale scopes are dropped and recent ones kept
    """
    recent = datetime.now(timezone.utc).isoformat()
    stale = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    (tmp_path / "repo.json").write_text(
        json.dumps(
            {
                "version": 1,
                "repository": "example.com/my/repo",
                "scopes": {
                    "recent": {
                        "completed": ["sha1"],
                        "failed": {},
                        "updated_at": recent,
                    },
                    "stale": {
                        "completed": ["sha2"],
                        "failed": {},
                        "updated_at": stale,
                    },
                },
            }
        )
    )

    progress = _make_progress(tmp_path, fingerprint="fingerprint-1")
    progress.save()

    data = json.loads((tmp_path / "repo.json").read_text())
    assert "recent" in data["scopes"]
    assert "stale" not in data["scopes"]


def test_create_uses_repository_url_identity(tmp_path, monkeypatch):
    """
    GIVEN a scan context pointing at a repository with an origin URL
    WHEN creating the progress tracker
    THEN the state file is named after the repository identity and lives in
    the cache directory
    """
    monkeypatch.setenv("GG_CACHE_DIR", str(tmp_path / "cache"))
    scan_context = ScanContext(
        scan_mode=ScanMode.COMMIT_RANGE,
        command_path="ggshield secret scan commit-range",
        target_path=tmp_path / "repo",
    )

    class FakeClient:
        base_uri = "https://api.example.com"

    with patch(
        "ggshield.core.scan_progress.get_repository_url_from_path",
        return_value="example.com/my/repo",
    ):
        progress = ScanProgress.create(
            client=FakeClient(),
            scan_context=scan_context,
            secret_config=SecretConfig(),
            exclusion_regexes=set(),
        )

    assert progress is not None
    assert progress.repository == "example.com/my/repo"
    assert progress.cache_path.parent == tmp_path / "cache" / "scan-progress"
    assert progress.cache_path.exists() is False

    progress.mark_completed(["sha1"])
    assert progress.cache_path.is_file()


def test_create_without_target_path_returns_none():
    """
    GIVEN a scan context without target path
    WHEN creating the progress tracker
    THEN None is returned
    """
    scan_context = ScanContext(
        scan_mode=ScanMode.COMMIT_RANGE,
        command_path="ggshield secret scan commit-range",
    )

    class FakeClient:
        base_uri = "https://api.example.com"

    assert (
        ScanProgress.create(
            client=FakeClient(),
            scan_context=scan_context,
            secret_config=SecretConfig(),
            exclusion_regexes=set(),
        )
        is None
    )


def test_create_falls_back_to_git_root(tmp_path, monkeypatch):
    """
    GIVEN a local repository without a remote
    WHEN creating the progress tracker
    THEN the resolved git directory path is used as identity
    """
    monkeypatch.setenv("GG_CACHE_DIR", str(tmp_path / "cache"))
    scan_context = ScanContext(
        scan_mode=ScanMode.REPO,
        command_path="ggshield secret scan repo",
        target_path=tmp_path / "repo",
    )

    class FakeClient:
        base_uri = "https://api.example.com"

    with (
        patch(
            "ggshield.core.scan_progress.get_repository_url_from_path",
            return_value=None,
        ),
        patch(
            "ggshield.core.scan_progress.get_git_root",
            return_value=tmp_path / "resolved-repo",
        ),
    ):
        progress = ScanProgress.create(
            client=FakeClient(),
            scan_context=scan_context,
            secret_config=SecretConfig(),
            exclusion_regexes=set(),
        )

    assert progress is not None
    assert progress.repository == str(tmp_path / "resolved-repo")


def test_create_never_raises(tmp_path):
    """
    GIVEN the identity resolution blows up
    WHEN creating the progress tracker
    THEN None is returned instead of breaking the scan
    """
    scan_context = ScanContext(
        scan_mode=ScanMode.COMMIT_RANGE,
        command_path="x",
        target_path=tmp_path,
    )

    class FakeClient:
        base_uri = "https://api.example.com"

    with patch(
        "ggshield.core.scan_progress.get_repository_url_from_path",
        side_effect=RuntimeError("git exploded"),
    ):
        assert (
            ScanProgress.create(
                client=FakeClient(),
                scan_context=scan_context,
                secret_config=SecretConfig(),
                exclusion_regexes=set(),
            )
            is None
        )
