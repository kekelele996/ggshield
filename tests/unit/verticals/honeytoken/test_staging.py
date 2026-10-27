"""Tests for the two-phase, all-or-nothing placement planner (``staging``)."""

import configparser
from pathlib import Path

import pytest
import yaml

from ggshield.verticals.honeytoken.endpoint_deployments import Deployment
from ggshield.verticals.honeytoken.staging import (
    CommitAborted,
    Plan,
    PlanStatus,
    build_user_plan,
    commit_plan,
    format_plan,
)
from ggshield.verticals.honeytoken.targets import Target


# --- fixtures / builders ----------------------------------------------------------


def _target(tmp_path: Path) -> Target:
    return Target(username="tester", home=tmp_path, uid=None)


def _aws_deployment(
    action: str = "write",
    *,
    dep_id: str = "dep-a",
    filename: str = "credentials",
    profile: str = "prod-backup",
    key: str = "AKIAEXAMPLE",
    secret: str = "s3cr3t",
    method: str = "aws_credentials",
) -> Deployment:
    return Deployment.from_dict(
        {
            "id": dep_id,
            "action": action,
            "method": method,
            "config": {"filename": filename, "profile_name": profile},
            "token": {"access_token_id": key, "secret_key": secret},
        }
    )


def _kube_text(subdomain: str, bearer: str) -> str:
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
    action: str = "write",
    *,
    dep_id: str = "dep-k",
    subdomain: str = "abc123",
    bearer: str = "s3cret",
) -> Deployment:
    return Deployment.from_dict(
        {
            "id": dep_id,
            "action": action,
            "method": "kubeconfig",
            "config": {"filename": "config"},
            "token": {
                "kubeconfig": _kube_text(subdomain, bearer),
                "context_name": f"kubernetes-admin-{subdomain}@{subdomain}",
            },
        }
    )


def _aws_section(path: Path, name: str) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    return dict(parser[name])


# --- planning ---------------------------------------------------------------------


def test_plan_two_new_writes(tmp_path):
    plan = Plan(
        users=[
            build_user_plan(
                _target(tmp_path),
                [_aws_deployment(), _kube_deployment()],
                force=False,
                running_as_root=False,
            )
        ]
    )
    assert not plan.has_blockers
    assert plan.written == 2
    assert plan.has_changes
    aws = plan.users[0].files[tmp_path / ".aws" / "credentials"]
    kube = plan.users[0].files[tmp_path / ".kube" / "config"]
    assert aws.baseline is None and aws.desired is not None
    assert kube.baseline is None and kube.desired is not None


def test_plan_identical_profile_is_no_change(tmp_path):
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    parser = configparser.ConfigParser(interpolation=None)
    parser["prod-backup"] = {
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "s3cr3t",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    user_plan = build_user_plan(
        _target(tmp_path), [_aws_deployment()], force=False, running_as_root=False
    )

    entry = user_plan.entries[0]
    assert entry.status is PlanStatus.ALREADY_CURRENT
    staged = user_plan.files[tmp_path / ".aws" / "credentials"]
    assert not staged.changed
    rendered = format_plan(Plan(users=[user_plan]), dry_run=True)
    assert "identical, already planted" in rendered


def test_plan_conflict_is_blocked_and_keeps_baseline(tmp_path):
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text(
        "[prod-backup]\naws_access_key_id = USER_OWN\naws_secret_access_key = mine\n"
    )

    user_plan = build_user_plan(
        _target(tmp_path), [_aws_deployment()], force=False, running_as_root=False
    )

    assert user_plan.entries[0].status is PlanStatus.BLOCKED
    assert "refusing to overwrite without --force" in user_plan.entries[0].problem
    staged = user_plan.files[tmp_path / ".aws" / "credentials"]
    assert not staged.changed
    assert Plan(users=[user_plan]).has_blockers


def test_plan_force_turns_conflict_into_write(tmp_path):
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text(
        "[prod-backup]\naws_access_key_id = USER_OWN\naws_secret_access_key = mine\n"
    )

    user_plan = build_user_plan(
        _target(tmp_path), [_aws_deployment()], force=True, running_as_root=False
    )

    assert user_plan.entries[0].status is PlanStatus.WRITE


def test_plan_collects_every_blocker_not_just_the_first(tmp_path):
    # Both targets are unparseable: the plan must surface both problems at once rather
    # than stop at the first.
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text("[\nnot an ini file")
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir()
    (kube_dir / "config").write_text("clusters: [unclosed flow sequence\n")

    user_plan = build_user_plan(
        _target(tmp_path),
        [_aws_deployment(), _kube_deployment()],
        force=False,
        running_as_root=False,
    )

    assert len(user_plan.entries) == 2
    assert all(entry.status is PlanStatus.BLOCKED for entry in user_plan.entries)
    problems = " ".join(entry.problem or "" for entry in user_plan.entries)
    assert "not a valid AWS" in problems
    assert "not a valid kubeconfig" in problems


def test_plan_rotation_sequences_delete_then_write_in_one_file(tmp_path):
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir()
    (kube_dir / "config").write_text(_kube_text("old111", "old-bearer"))

    user_plan = build_user_plan(
        _target(tmp_path),
        [
            _kube_deployment(
                "delete", dep_id="dep-old", subdomain="old111", bearer="old-bearer"
            ),
            _kube_deployment(
                "write", dep_id="dep-new", subdomain="new222", bearer="new-bearer"
            ),
        ],
        force=False,
        running_as_root=False,
    )

    statuses = [e.status for e in user_plan.entries]
    assert PlanStatus.REMOVE in statuses and PlanStatus.WRITE in statuses
    # Both collapse to one file: the new content, the old bearer gone.
    staged_files = list(user_plan.files.values())
    assert len(staged_files) == 1
    assert "new-bearer" in staged_files[0].desired
    assert "old-bearer" not in staged_files[0].desired


def test_plan_labels_identity_and_companions(tmp_path):
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    parser = configparser.ConfigParser(interpolation=None)
    parser["default"] = {
        "aws_access_key_id": "USER_OWN",
        "aws_secret_access_key": "mine",
    }
    with open(aws_dir / "credentials", "w") as handle:
        parser.write(handle)

    rendered = format_plan(
        Plan(
            users=[
                build_user_plan(
                    _target(tmp_path),
                    [_aws_deployment()],
                    force=False,
                    running_as_root=False,
                )
            ]
        ),
        dry_run=True,
    )

    assert "aws profile [prod-backup]" in rendered
    assert "access key id AKIAEXAMPLE" in rendered
    assert "s3cr3t" not in rendered
    assert "file also holds: profile [default]" in rendered
    assert "Summary: 1 to write" in rendered


def test_plan_kube_identity_names_cluster_server_user(tmp_path):
    rendered = format_plan(
        Plan(
            users=[
                build_user_plan(
                    _target(tmp_path),
                    [_kube_deployment()],
                    force=False,
                    running_as_root=False,
                )
            ]
        ),
        dry_run=True,
    )
    assert "kubeconfig context [kubernetes-admin-abc123@abc123]" in rendered
    assert "cluster [abc123] (https://abc123.orionfleet.io)" in rendered
    assert "user [kubernetes-admin-abc123]" in rendered
    assert "s3cret" not in rendered


# --- commit -----------------------------------------------------------------------


def test_commit_applies_whole_plan(tmp_path):
    plan = Plan(
        users=[
            build_user_plan(
                _target(tmp_path),
                [_aws_deployment(), _kube_deployment()],
                force=False,
                running_as_root=False,
            )
        ]
    )
    commit_plan(plan, running_as_root=False)

    assert _aws_section(tmp_path / ".aws" / "credentials", "prod-backup") == {
        "aws_access_key_id": "AKIAEXAMPLE",
        "aws_secret_access_key": "s3cr3t",
    }
    doc = yaml.safe_load((tmp_path / ".kube" / "config").read_text())
    assert doc["contexts"][0]["name"] == "kubernetes-admin-abc123@abc123"


def test_commit_then_replan_is_a_noop(tmp_path):
    deployments = [_aws_deployment()]
    plan = Plan(
        users=[
            build_user_plan(
                _target(tmp_path), deployments, force=False, running_as_root=False
            )
        ]
    )
    commit_plan(plan, running_as_root=False)

    replanned = Plan(
        users=[
            build_user_plan(
                _target(tmp_path), deployments, force=False, running_as_root=False
            )
        ]
    )
    assert not replanned.has_changes
    assert replanned.written == 0
    assert replanned.skipped == 1
    # Committing a no-op plan must leave the file byte-identical.
    before = (tmp_path / ".aws" / "credentials").read_bytes()
    commit_plan(replanned, running_as_root=False)
    assert (tmp_path / ".aws" / "credentials").read_bytes() == before


def test_commit_blocked_plan_refuses(tmp_path):
    (tmp_path / ".aws").mkdir()
    (tmp_path / ".aws" / "credentials").write_text(
        "[prod-backup]\naws_access_key_id = USER_OWN\naws_secret_access_key = mine\n"
    )
    plan = Plan(
        users=[
            build_user_plan(
                _target(tmp_path),
                [_aws_deployment()],
                force=False,
                running_as_root=False,
            )
        ]
    )
    assert plan.has_blockers
    with pytest.raises(CommitAborted):
        commit_plan(plan, running_as_root=False)


def test_commit_drifted_file_aborts_before_publishing(tmp_path):
    plan = Plan(
        users=[
            build_user_plan(
                _target(tmp_path),
                [_aws_deployment(), _kube_deployment()],
                force=False,
                running_as_root=False,
            )
        ]
    )
    # Hand-edit a target (create the file with foreign content) after planning.
    (tmp_path / ".kube").mkdir(parents=True)
    (tmp_path / ".kube" / "config").write_text(
        "# hand edited after the plan\napiVersion: v1\nkind: Config\n"
    )

    with pytest.raises(CommitAborted) as excinfo:
        commit_plan(plan, running_as_root=False)
    assert "changed since the plan was reviewed" in str(excinfo.value)
    # Nothing landed for the other, healthy target either, and its freshly created
    # placement directory is removed on abort.
    assert not (tmp_path / ".aws" / "credentials").exists()
    assert not (tmp_path / ".aws").exists()
    # The drifted file is untouched (its pre-existing directory stays).
    assert "hand edited after the plan" in (tmp_path / ".kube" / "config").read_text()


def test_commit_publish_failure_restores_baseline_byte_for_byte(tmp_path, monkeypatch):
    # The AWS file pre-exists with real content; the kubeconfig publish (second file)
    # fails. Rollback must restore the AWS file exactly and leave no half group.
    from ggshield.verticals.honeytoken import secure_file

    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    original = (
        "# my real credentials\n"
        "[default]\n"
        "aws_access_key_id = USER_OWN\n"
        "aws_secret_access_key = mine\n"
    )
    (aws_dir / "credentials").write_text(original)

    plan = Plan(
        users=[
            build_user_plan(
                _target(tmp_path),
                [_aws_deployment(), _kube_deployment()],
                force=False,
                running_as_root=False,
            )
        ]
    )

    real_write = secure_file.atomic_write_via_fd

    def _fail_kube(dir_fd, name, content, owner=None):
        if name == "config":
            raise OSError("disk full")
        return real_write(dir_fd, name, content, owner)

    monkeypatch.setattr(secure_file, "atomic_write_via_fd", _fail_kube)

    with pytest.raises(CommitAborted) as excinfo:
        commit_plan(plan, running_as_root=False)
    assert "disk full" in str(excinfo.value)
    # The AWS file is back to its exact pre-run bytes; the kube file and the directory
    # created for the failed publish are both gone.
    assert (aws_dir / "credentials").read_text() == original
    assert (
        _aws_section(aws_dir / "credentials", "default")["aws_access_key_id"]
        == "USER_OWN"
    )
    assert not (tmp_path / ".kube" / "config").exists()
    assert not (tmp_path / ".kube").exists()


def test_remove_only_plan_suppresses_writes(tmp_path):
    user_plan = build_user_plan(
        _target(tmp_path),
        [
            _aws_deployment("write"),
            _aws_deployment("delete", dep_id="dep-b", key="OLD"),
        ],
        force=False,
        running_as_root=False,
        remove_only=True,
    )
    assert user_plan.suppressed_writes == 1
    assert [e.deployment.id for e in user_plan.entries] == ["dep-b"]
