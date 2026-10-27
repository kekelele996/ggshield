import configparser
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest
import yaml
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok
from tests.unit.request_mock import ExpectedRequest, RequestMock, create_json_response


ENDPOINT = "/v1/honeytokens/endpoint-deployments"


def _deployment(
    action: str,
    *,
    dep_id: str = "dep-1",
    method: str = "aws_credentials",
    filename: str = "credentials",
    profile: str = "prod-backup",
    token: Optional[Tuple[str, str]] = None,
) -> Dict[str, Any]:
    deployment: Dict[str, Any] = {
        "id": dep_id,
        "action": action,
        "method": method,
        "config": {"filename": filename, "profile_name": profile},
    }
    if token is not None:
        deployment["token"] = {"access_token_id": token[0], "secret_key": token[1]}
    return deployment


def _install_mock(monkeypatch) -> RequestMock:
    mock = RequestMock()
    monkeypatch.setattr("ggshield.core.client.Session.request", mock)
    return mock


def _section(path: Path, name: str) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    return dict(parser[name])


def test_help(cli_fs_runner: CliRunner) -> None:
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--help"])
    assert_invoke_ok(result)
    assert "plant" in result.output.lower()


def test_list_targets_no_api_call(cli_fs_runner: CliRunner) -> None:
    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--user-dir", "home", "--list-targets"]
    )
    assert_invoke_ok(result)
    assert "Would plant for 1 user(s)" in result.output


def test_plant_writes_profile(cli_fs_runner: CliRunner, monkeypatch) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "aws", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert _section(Path("home/.aws/credentials"), "prod-backup") == {
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "s3cr3t",
    }


def test_plant_is_idempotent(cli_fs_runner: CliRunner, monkeypatch) -> None:
    # Pre-existing profile with the same creds → AlreadyCurrent → confirmed planted.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "s3cr3t",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    assert "0 written, 1 skipped" in result.output


def test_remove_only_uses_get_and_removes_revoked(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # On-disk profile holds the revoked key → verify-before-remove deletes it.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    # GET (read-only cleanup) returns a delete carrying the revoked key.
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert not (aws_dir / "credentials").exists()
    assert "1 removed" in result.output


def test_remove_only_reapplies_ownership_when_file_survives(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A delete that leaves OTHER profiles rewrites the file (temp + os.replace). As root
    # that leaves it root-owned 0600, locking the user out — ownership/perms must be
    # re-applied. Here we record the call to prove the re-apply happens.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    parser["default"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    from ggshield.verticals.honeytoken import staging

    fixed_up: list = []
    real_fixup = staging._fixup_dirs_via_fd

    def _spy_fixup(dirs, files, running_as_root):
        fixed_up.extend(files)
        return real_fixup(dirs, files, running_as_root)

    monkeypatch.setattr(staging, "_fixup_dirs_via_fd", _spy_fixup)

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    # The file survived (the foreign 'default' profile remains) and its directory was
    # re-permed/handed back as part of the atomic commit.
    assert (aws_dir / "credentials").exists()
    assert Path("home/.aws/credentials") in [f.path for f in fixed_up]
    # The user's own profile is intact.
    assert (
        _section(aws_dir / "credentials", "default")["aws_access_key_id"] == "USER_OWN"
    )


def test_remove_only_skips_reapply_when_file_deleted(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # When ours was the only profile, the file is unlinked — there's nothing left to
    # re-perm, so apply_dir_perms_and_owner must NOT run.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    from ggshield.verticals.honeytoken import staging

    fixed_up: list = []
    monkeypatch.setattr(
        staging,
        "_fixup_dirs_via_fd",
        lambda dirs, files, running_as_root: fixed_up.extend(files),
    )

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    assert not (aws_dir / "credentials").exists()
    # No surviving file → the directory is not re-permed/chowned.
    assert fixed_up == []


def test_malformed_credentials_file_fails_cleanly(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A garbage ~/.aws/credentials must not crash with a traceback: the deployment is
    # reported failed and the run exits non-zero with a clean message.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    (aws_dir / "credentials").write_text("[\nthis is not a valid ini file")

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "could not parse" in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="passwd lookup is POSIX")
def test_unknown_user_is_usage_error(cli_fs_runner: CliRunner) -> None:
    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--user", "ghost-nonexistent-xyz"]
    )
    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "could not resolve home directory" in result.output


def test_write_entry_missing_credentials_fails(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response({"deployments": [_deployment("write", token=None)]}),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "missing credentials" in result.output


def test_confirm_failure_is_logged_not_fatal(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The profile is written; the confirm PATCH fails → logged, run still succeeds.
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest(
            "PATCH", f"{ENDPOINT}/dep-1", create_json_response({"detail": "boom"}, 500)
        )
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    assert "could not confirm" in result.output
    assert Path("home/.aws/credentials").exists()


def test_target_resolution_failure_is_clean(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # e.g. pwd.getpwall() blowing up during a root fan-out: no traceback.
    def _boom(*_a, **_k):
        raise RuntimeError("pwd exploded")

    monkeypatch.setattr("ggshield.cmd.honeytoken.plant.resolve_targets", _boom)
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant"])
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "could not resolve planting targets" in result.output


def test_unexpected_per_target_error_does_not_crash(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # Last-resort net: an unexpected failure while planning a target is reported, not
    # raised, and aborts the run before any file is written.
    def _boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr("ggshield.cmd.honeytoken.plant.build_user_plan", _boom)
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "unexpected error" in result.output
    assert not Path("home/.aws/credentials").exists()


def test_api_auth_error_exits_authentication(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A 403 from the reconcile POST → AUTHENTICATION_ERROR, reported cleanly, no write.
    mock = _install_mock(monkeypatch)
    mock.add_POST(ENDPOINT, create_json_response({"detail": "forbidden"}, 403))
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_exited_with(result, ExitCode.AUTHENTICATION_ERROR)
    assert not Path("home/.aws/credentials").exists()


def test_remove_only_foreign_profile_is_kept(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The on-disk profile holds a DIFFERENT key than the revoked token → verify-before-
    # remove leaves it untouched (never clobber a foreign profile). The revoked decoy is
    # nonetheless gone from disk, so the deployment is confirmed removed: reporting a
    # failure would keep the delete pending on every later run.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "SOMEONE_ELSE",
        "aws_secret_access_key": "x",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.SUCCESS)
    mock.assert_all_requests_happened()
    assert "left untouched" in result.output
    assert "0 written, 0 skipped, 1 removed" in result.output
    # The foreign profile is preserved verbatim.
    assert (
        _section(aws_dir / "credentials", "prod-backup")["aws_access_key_id"]
        == "SOMEONE_ELSE"
    )


def test_remove_only_delete_failure_is_reported(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A malformed ~/.aws during the delete pass is reported per-deployment (FAILED), not
    # a crash; the run exits non-zero with a clean message.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    (aws_dir / "credentials").write_text("[\nthis is not a valid ini file")

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "could not parse" in result.output


def test_unknown_action_is_ignored(cli_fs_runner: CliRunner, monkeypatch) -> None:
    # A forward-compat action a newer backend introduced is logged, not fatal.
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT, create_json_response({"deployments": [_deployment("freeze")]})
    )
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    assert "ignoring unknown action" in result.output


def test_foreign_profile_without_force_fails(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # On-disk profile holds a different key; a write without --force must refuse.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    # The user's own profile is left untouched.
    assert (
        _section(Path("home/.aws/credentials"), "prod-backup")["aws_access_key_id"]
        == "USER_OWN"
    )


# --- kubeconfig placement through the CLI --------------------------------------------


def _kubeconfig_text(subdomain: str, bearer: str) -> str:
    user = f"kubernetes-admin-{subdomain}"
    return yaml.safe_dump(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [
                {
                    "name": subdomain,
                    "cluster": {"server": f"https://{subdomain}.orionfleet.io"},
                }
            ],
            "users": [{"name": user, "user": {"token": bearer}}],
            "contexts": [
                {
                    "name": f"{user}@{subdomain}",
                    "context": {"cluster": subdomain, "user": user},
                }
            ],
        },
        sort_keys=False,
    )


def _kube_deployment(
    action: str, *, dep_id: str, subdomain: str, bearer: str
) -> Dict[str, Any]:
    return {
        "id": dep_id,
        "action": action,
        "method": "kubeconfig",
        "config": {"filename": "config"},
        "token": {
            "kubeconfig": _kubeconfig_text(subdomain, bearer),
            "context_name": f"kubernetes-admin-{subdomain}@{subdomain}",
        },
    }


def _kube_doc(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_plant_kubeconfig_writes_context(cli_fs_runner: CliRunner, monkeypatch) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    )
                ]
            }
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-k", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "plant",
            "--type",
            "kubeconfig",
            "--method",
            "kubeconfig",
            "--user-dir",
            "home",
        ],
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    doc = _kube_doc(Path("home/.kube/config"))
    assert [ctx["name"] for ctx in doc["contexts"]] == [
        "kubernetes-admin-abc123@abc123"
    ]
    assert doc["users"][0]["user"]["token"] == "s3cret"
    assert doc["current-context"] == "kubernetes-admin-abc123@abc123"
    assert "1 written, 0 skipped, 0 removed" in result.output


def test_plant_kubeconfig_rotation_removes_old_then_writes_new(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The revoked decoy is already on disk; one reconcile returns delete(old) + write(new)
    # for the same file — deletes run first, then the write.
    kube_dir = Path("home/.kube")
    kube_dir.mkdir(parents=True)
    (kube_dir / "config").write_text(
        _kubeconfig_text("old111", "old-bearer"), encoding="utf-8"
    )

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _kube_deployment(
                        "delete",
                        dep_id="dep-old",
                        subdomain="old111",
                        bearer="old-bearer",
                    ),
                    _kube_deployment(
                        "write",
                        dep_id="dep-new",
                        subdomain="new222",
                        bearer="new-bearer",
                    ),
                ]
            }
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-old", create_json_response({}, 200))
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-new", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "kubeconfig", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    doc = _kube_doc(kube_dir / "config")
    assert [ctx["name"] for ctx in doc["contexts"]] == [
        "kubernetes-admin-new222@new222"
    ]
    assert "old-bearer" not in (kube_dir / "config").read_text(encoding="utf-8")
    assert "1 written, 0 skipped, 1 removed" in result.output


def test_plant_applies_every_live_deployment_whatever_the_type(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # Reconcile returns the endpoint's whole desired state: an AWS profile and a
    # kubeconfig context are both materialized in one run, `--type` only steered creation.
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _deployment("write", dep_id="dep-a", token=("AKIAEXAMPLE", "s3")),
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    ),
                ]
            }
        ),
    )
    for dep_id in ("dep-a", "dep-k"):
        mock.add_request(
            ExpectedRequest(
                "PATCH", f"{ENDPOINT}/{dep_id}", create_json_response({}, 200)
            )
        )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "kubeconfig", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert Path("home/.aws/credentials").exists()
    assert Path("home/.kube/config").exists()
    assert "2 written" in result.output


# --- kubeconfig failure paths through the CLI -------------------------------------------


def test_kubeconfig_delete_without_token_blocks_the_group(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The server always ships the token on delete; a payload without it cannot be applied
    # safely. Under all-or-nothing placement it blocks the plan: no writes AND no
    # placement confirmations (nothing was attempted).
    mock = _install_mock(monkeypatch)
    deployment = _kube_deployment(
        "delete", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
    )
    del deployment["token"]
    mock.add_GET(ENDPOINT, create_json_response({"deployments": [deployment]}))

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    # Only the GET happened; no PATCH confirmation was sent.
    mock.assert_all_requests_happened()
    assert "missing its kubeconfig identity" in result.output
    assert "blocking problem" in result.output
    assert not Path("home/.kube/config").exists()


def test_kubeconfig_foreign_token_on_delete_is_kept_but_confirmed_removed(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # Our context is on disk but its bearer was rotated by someone else → verify-before-
    # remove keeps it. Our revoked bearer is no longer there, so the delete is confirmed
    # removed and stops coming back.
    kube_dir = Path("home/.kube")
    kube_dir.mkdir(parents=True)
    (kube_dir / "config").write_text(
        _kubeconfig_text("abc123", "rotated-by-someone-else"), encoding="utf-8"
    )
    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _kube_deployment(
                        "delete", dep_id="dep-k", subdomain="abc123", bearer="planted"
                    )
                ]
            }
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-k", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.SUCCESS)
    assert "left untouched" in result.output
    assert "0 written, 0 skipped, 1 removed" in result.output
    assert "rotated-by-someone-else" in (kube_dir / "config").read_text(
        encoding="utf-8"
    )


def test_kubeconfig_foreign_entry_without_force_is_a_clean_refusal(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # A real user already carries our (scoped) user name with another token: the
    # kubeconfig ForceRefusal must be caught by the plant loop like the AWS one.
    kube_dir = Path("home/.kube")
    kube_dir.mkdir(parents=True)
    (kube_dir / "config").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [],
                "users": [
                    {
                        "name": "kubernetes-admin-abc123",
                        "user": {"token": "real-admin-token"},
                    }
                ],
                "contexts": [],
            }
        ),
        encoding="utf-8",
    )
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    )
                ]
            }
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-k", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "kubeconfig", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "refusing to overwrite without --force" in result.output
    assert "Traceback" not in result.output
    assert "real-admin-token" in (kube_dir / "config").read_text(encoding="utf-8")


def test_publish_failure_aborts_and_rolls_back(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # Two new files in one group: the first publish succeeds, the second fails. The
    # atomic commit must roll the first file back to its planned baseline (absent here)
    # and report the abort — no placement confirmation is sent for a partial group.
    from ggshield.verticals.honeytoken import secure_file

    real_write = secure_file.atomic_write_via_fd
    calls = {"n": 0}

    def _fail_second(dir_fd, name, content, owner=None):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real_write(dir_fd, name, content, owner)

    monkeypatch.setattr(secure_file, "atomic_write_via_fd", _fail_second)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _deployment("write", dep_id="dep-a", token=("AKIAEXAMPLE", "s3")),
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    ),
                ]
            }
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "kubeconfig", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "disk full" in result.output
    assert "rolled back" in result.output
    # Nothing survives: the file published first was restored to absent, and the
    # directories the commit created for the group are gone too.
    assert not Path("home/.aws/credentials").exists()
    assert not Path("home/.kube/config").exists()
    assert not Path("home/.aws").exists()
    assert not Path("home/.kube").exists()


def test_unknown_method_on_write_says_client_may_be_out_of_date(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    mock = _install_mock(monkeypatch)
    deployment = _deployment("write", token=("AKIAEXAMPLE", "s3"))
    deployment["method"] = "teleport_profile"
    mock.add_POST(ENDPOINT, create_json_response({"deployments": [deployment]}))

    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "client may be out of date" in result.output
    assert "missing credentials" not in result.output
    # A blocked group sends no confirmations and writes nothing.
    mock.assert_all_requests_happened()
    assert not Path("home/.aws/credentials").exists()


# --- plan-first, all-or-nothing placement -----------------------------------------


def test_plan_dry_run_writes_nothing_and_shows_account_identity(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--plan", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    # Only the reconcile POST happened: no disk write, no placement confirmation.
    mock.assert_all_requests_happened()
    assert not Path("home/.aws/credentials").exists()
    # The plan names the account/profile the decoy belongs to (key id, never secret).
    assert "Placement plan" in result.output
    assert "aws profile [prod-backup]" in result.output
    assert "access key id AKIAEXAMPLE" in result.output
    assert "s3cr3t" not in result.output
    assert "1 to write" in result.output


def test_plan_dry_run_shows_kube_cluster_identity(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    )
                ]
            }
        ),
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "plant",
            "--plan",
            "--type",
            "kubeconfig",
            "--method",
            "kubeconfig",
            "--user-dir",
            "home",
        ],
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert not Path("home/.kube/config").exists()
    # Which cluster/context/user the decoy belongs to (no bearer leaked).
    assert "kubeconfig context [kubernetes-admin-abc123@abc123]" in result.output
    assert "cluster [abc123] (https://abc123.orionfleet.io)" in result.output
    assert "user [kubernetes-admin-abc123]" in result.output
    assert "s3cret" not in result.output


def test_plan_lists_other_identities_sharing_the_file(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The operator's real profile already lives in the target file: the plan says so.
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["default"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--plan", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    assert "file also holds: profile [default]" in result.output


def test_plan_blocked_exits_nonzero_without_writing(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--plan", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    mock.assert_all_requests_happened()
    assert "BLOCKED" in result.output
    assert "blocking problem" in result.output
    # The foreign profile is exactly as it was.
    assert (
        _section(aws_dir / "credentials", "prod-backup")["aws_access_key_id"]
        == "USER_OWN"
    )


def test_conflict_on_second_file_leaves_first_file_untouched(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The story from the issue: the AWS profile would plant fine, but the kubeconfig
    # target holds someone else's identity. Nothing must land anywhere.
    kube_dir = Path("home/.kube")
    kube_dir.mkdir(parents=True)
    (kube_dir / "config").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [],
                "users": [
                    {
                        "name": "kubernetes-admin-abc123",
                        "user": {"token": "real-admin-token"},
                    }
                ],
                "contexts": [],
            }
        ),
        encoding="utf-8",
    )

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _deployment("write", dep_id="dep-a", token=("AKIAEXAMPLE", "s3")),
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    ),
                ]
            }
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "kubeconfig", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "blocking problem" in result.output
    # No half group: the healthy target was never written either.
    assert not Path("home/.aws/credentials").exists()
    assert "real-admin-token" in (kube_dir / "config").read_text(encoding="utf-8")
    assert "s3cret" not in (kube_dir / "config").read_text(encoding="utf-8")
    # No placement confirmations for an aborted group.
    mock.assert_all_requests_happened()


def test_file_changed_after_plan_aborts_before_publishing(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    # The kubeconfig is hand-edited in the window between planning and the commit's
    # verify step: the whole group stops, and the healthy AWS file never lands.
    from ggshield.verticals.honeytoken import secure_file

    # The file exists at plan time with an unrelated, real context; the plan merges
    # our decoy beside it.
    kube_dir = Path("home/.kube")
    kube_dir.mkdir(parents=True)
    (kube_dir / "config").write_text(
        yaml.safe_dump(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [
                    {"name": "real", "cluster": {"server": "https://real.example"}}
                ],
                "users": [{"name": "real-user", "user": {"token": "real-token"}}],
                "contexts": [
                    {
                        "name": "real-user@real",
                        "context": {"cluster": "real", "user": "real-user"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    real_read = secure_file.read_via_fd
    reads: Dict[str, int] = {}

    def _read_tracking(dir_fd, name):
        reads[name] = reads.get(name, 0) + 1
        if name == "config" and reads[name] == 2:
            # Second read is the commit-time verification: someone swapped the file.
            return "apiVersion: v1\nkind: Config\n# hand edited after the plan\n"
        return real_read(dir_fd, name)

    monkeypatch.setattr(secure_file, "read_via_fd", _read_tracking)

    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {
                "deployments": [
                    _deployment("write", dep_id="dep-a", token=("AKIAEXAMPLE", "s3")),
                    _kube_deployment(
                        "write", dep_id="dep-k", subdomain="abc123", bearer="s3cret"
                    ),
                ]
            }
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--type", "kubeconfig", "--user-dir", "home"]
    )

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "changed since the plan was reviewed" in result.output
    assert not Path("home/.aws/credentials").exists()
    # The directory the aborting commit pre-created for the healthy AWS target is
    # removed too: the machine is byte-for-byte as it was.
    assert not Path("home/.aws").exists()
    # The existing kubeconfig was neither merged into nor overwritten.
    assert kube_dir.exists()
    kube_text = (kube_dir / "config").read_text(encoding="utf-8")
    assert "real-token" in kube_text
    assert "abc123" not in kube_text
    mock.assert_all_requests_happened()


def test_confirmation_prompt_decline_writes_nothing(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    monkeypatch.setattr("ggshield.cmd.honeytoken.plant._is_interactive", lambda: True)
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--user-dir", "home"], input="n\n"
    )

    assert_invoke_ok(result)
    assert "Aborted; no files were changed" in result.output
    assert not Path("home/.aws/credentials").exists()
    mock.assert_all_requests_happened()


def test_confirmation_prompt_accept_commits(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    monkeypatch.setattr("ggshield.cmd.honeytoken.plant._is_interactive", lambda: True)
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--user-dir", "home"], input="y\n"
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert Path("home/.aws/credentials").exists()


def test_yes_skips_prompt_and_commits(cli_fs_runner: CliRunner, monkeypatch) -> None:
    # Even when stdin is a TTY, --yes commits the reviewed plan without asking.
    monkeypatch.setattr("ggshield.cmd.honeytoken.plant._is_interactive", lambda: True)
    mock = _install_mock(monkeypatch)
    mock.add_POST(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
        ),
    )
    mock.add_request(
        ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--yes", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert Path("home/.aws/credentials").exists()


def test_running_twice_plants_no_second_copy(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    def _one_response():
        mock = _install_mock(monkeypatch)
        mock.add_POST(
            ENDPOINT,
            create_json_response(
                {"deployments": [_deployment("write", token=("AKIAEXAMPLE", "s3cr3t"))]}
            ),
        )
        mock.add_request(
            ExpectedRequest("PATCH", f"{ENDPOINT}/dep-1", create_json_response({}, 200))
        )
        return mock

    first = _one_response()
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    first.assert_all_requests_happened()
    assert "1 written, 0 skipped" in result.output
    after_first = Path("home/.aws/credentials").read_text()

    second = _one_response()
    result = cli_fs_runner.invoke(cli, ["honeytoken", "plant", "--user-dir", "home"])
    assert_invoke_ok(result)
    second.assert_all_requests_happened()
    assert "0 written, 1 skipped" in result.output
    # The second run changed nothing on disk.
    assert Path("home/.aws/credentials").read_text() == after_first


def test_plan_remove_only_shows_remove_without_touching_disk(
    cli_fs_runner: CliRunner, monkeypatch
) -> None:
    aws_dir = Path("home/.aws")
    aws_dir.mkdir(parents=True)
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "REVOKED",
        "aws_secret_access_key": "old",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    mock = _install_mock(monkeypatch)
    mock.add_GET(
        ENDPOINT,
        create_json_response(
            {"deployments": [_deployment("delete", token=("REVOKED", "old"))]}
        ),
    )

    result = cli_fs_runner.invoke(
        cli, ["honeytoken", "plant", "--plan", "--remove-only", "--user-dir", "home"]
    )

    assert_invoke_ok(result)
    mock.assert_all_requests_happened()
    assert "[remove]" in result.output
    # Dry run: the revoked profile is still on disk.
    assert _section(aws_dir / "credentials", "prod-backup") is not None
