import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import ExitCode
from ggshield.verticals.honeytoken.endpoint_deployments import (
    ConfirmStatus,
    Deployment,
    DeploymentAction,
    EndpointDeploymentsClient,
    EndpointDeploymentsError,
)
from ggshield.verticals.honeytoken.staging import (
    CommitAborted,
    Plan,
    PlanStatus,
    UserPlan,
    build_user_plan,
    commit_plan,
    format_plan,
)
from ggshield.verticals.honeytoken.targets import (
    Target,
    is_root,
    machine_info_for,
    resolve_targets,
)


@dataclass
class _Outcome:
    """Per-run reconciliation result, aggregated into the final exit code."""

    api_failure: bool = False
    api_auth_failure: bool = False
    fs_failure: bool = False


def _is_interactive() -> bool:
    """Whether to ask for confirmation before committing. Agents/CI (pipes, the test
    runner, a non-TTY stdin) apply directly; an operator at a terminal reviews the plan
    and confirms first. ``--yes`` skips the prompt explicitly."""
    try:
        return bool(sys.stdin is not None and sys.stdin.isatty())
    except Exception:  # noqa: BLE001 - a closed/replaced stdin must not crash the run
        return False


@click.command()
@click.option(
    "--type",
    "token_type",
    default="aws",
    help="Honeytoken type to create for this machine (aws, kubeconfig). Existing "
    "deployments of every type are synchronized regardless.",
)
@click.option(
    "--method",
    type=click.Choice(["aws_credentials", "aws_config_profile", "kubeconfig"]),
    default=None,
    help="Placement method for a new deployment (defaults to the type's method).",
)
@click.option(
    "--filename",
    default=None,
    help="Override the on-disk basename for a new deployment (safe charset only).",
)
@click.option(
    "--profile-name",
    "profile_name",
    default=None,
    help="Override the AWS profile/section name for a new deployment (AWS methods only).",
)
@click.option(
    "--user",
    default=None,
    help="Target OS user (defaults to the current user; as root, narrows the fan-out).",
)
@click.option(
    "--user-dir",
    "user_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the resolved home directory (single-user; testing).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite the honeytoken entry (AWS profile or kubeconfig context) if it "
    "exists and is not ours. Never touches a cluster/user a real context still uses.",
)
@click.option(
    "--list-targets",
    "list_targets",
    is_flag=True,
    help="Print the resolved planting targets and exit (no API call, no disk writes).",
)
@click.option(
    "--plan",
    "plan_only",
    is_flag=True,
    help="Check every target and print the placement plan — with the account/profile or "
    "cluster/context each entry belongs to — then exit. No disk writes and no placement "
    "confirmations; exits non-zero if any target conflicts.",
)
@click.option(
    "--yes",
    "-y",
    "assume_yes",
    is_flag=True,
    help="Apply the plan without the confirmation prompt (non-interactive runs).",
)
@click.option(
    "--remove-only",
    "remove_only",
    is_flag=True,
    help="Cleanup-only: read current state (read-only) and apply only `delete` actions.",
)
@add_common_options()
@click.pass_context
def plant_cmd(
    ctx: click.Context,
    token_type: str,
    method: Optional[str],
    filename: Optional[str],
    profile_name: Optional[str],
    user: Optional[str],
    user_dir: Optional[Path],
    force: bool,
    list_targets: bool,
    plan_only: bool,
    assume_yes: bool,
    remove_only: bool,
    **kwargs: Any,
) -> int:
    """
    Detect endpoint intrusion by planting a honeytoken on this machine.

    Placement is two-phase: every target file is checked read-only first and the full
    placement plan is shown (which AWS profile/access key or kubeconfig cluster/context
    lands in which file, alongside the identities already sharing it). On confirmation
    the whole plan is committed at once: if any target conflicts, is unreadable, or
    changes between the plan and the commit, nothing is written and earlier files are
    rolled back — a run never lands half a group. Re-running the command finds entries
    already in place and never plants a second copy.

    Honeytokens deployed are fully synchronized with the GitGuardian platform:
    write/refresh the decoy for `write` entries (an AWS credentials profile under
    `~/.aws/`, or a kubeconfig context under `~/.kube/`), remove it for `delete`
    (revoked) entries, preserving any other profiles/contexts the user already has.
    ggshield never revokes a honeytoken; it only reports placement status.

    Authorize with the `honeytokens:write` scope.
    """
    try:
        targets = resolve_targets(user, user_dir)
    except LookupError as exc:
        click.echo(str(exc), err=True)
        return ExitCode.USAGE_ERROR
    except Exception as exc:  # noqa: BLE001 - never crash resolving targets (e.g. pwd)
        click.echo(f"could not resolve planting targets: {exc}", err=True)
        return ExitCode.UNEXPECTED_ERROR
    if not targets:
        click.echo("No target users to plant honeytokens for.", err=True)
        return ExitCode.USAGE_ERROR

    if list_targets:
        click.echo(f"Would plant for {len(targets)} user(s) [type={token_type}]:")
        for target in targets:
            uid = f"uid {target.uid}" if target.uid is not None else "uid -"
            click.echo(f"  {target.username}  ({uid})  at {target.home}")
        return ExitCode.SUCCESS

    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    gg_client = create_client_from_config(config)
    client = EndpointDeploymentsClient(
        gg_client.session, config.api_url, config.api_key
    )
    running_as_root = is_root()

    # Phase 0: fetch the desired state for EVERY user first. An API failure for one
    # target aborts the run before any file is considered, instead of planting for the
    # users that responded.
    final = _Outcome()
    fetched: List[Tuple[Target, List[Deployment]]] = []
    for target in targets:
        try:
            if remove_only:
                deployments = client.list(
                    machine_info_for(target.username)["machine_id"], target.username
                )
            else:
                deployments = client.reconcile(
                    machine_info_for(target.username),
                    token_type,
                    method=method,
                    filename=filename,
                    profile_name=profile_name,
                )
        except EndpointDeploymentsError as exc:
            click.echo(f"[{target.username}] {exc}", err=True)
            final.api_failure = True
            final.api_auth_failure = exc.is_auth
            continue
        fetched.append((target, deployments))

    if final.api_auth_failure:
        return ExitCode.AUTHENTICATION_ERROR
    if final.api_failure:
        click.echo(
            "Placement aborted: could not fetch the desired state for every target, "
            "so no files were changed.",
            err=True,
        )
        return ExitCode.UNEXPECTED_ERROR

    # Phase 1: plan — read-only staging for the whole group, all problems collected.
    plan = Plan()
    for target, deployments in fetched:
        try:
            user_plan = build_user_plan(
                target,
                deployments,
                force=force,
                running_as_root=running_as_root,
                remove_only=remove_only,
            )
        except Exception as exc:  # noqa: BLE001 - never crash planning a target
            click.echo(f"[{target.username}] unexpected error: {exc}", err=True)
            final.fs_failure = True
            continue
        plan.users.append(user_plan)
    if final.fs_failure:
        click.echo(
            "Placement aborted: planning failed for at least one target, so no files "
            "were changed.",
            err=True,
        )
        return ExitCode.UNEXPECTED_ERROR

    click.echo(format_plan(plan, dry_run=plan_only))

    if plan_only:
        return ExitCode.UNEXPECTED_ERROR if plan.has_blockers else ExitCode.SUCCESS

    if plan.has_blockers:
        click.echo(
            "Placement aborted: resolve the blocking problem(s) above "
            "(or re-run with --force for a same-named foreign entry); no files were "
            "changed.",
            err=True,
        )
        return ExitCode.UNEXPECTED_ERROR

    # Phase 2 gate: an interactive operator confirms the reviewed plan; non-interactive
    # runs (agents, pipes) and --yes skip the prompt.
    if plan.has_changes and not assume_yes and _is_interactive():
        if not click.confirm("\nProceed with this placement?", default=False):
            click.echo("Aborted; no files were changed.")
            return ExitCode.SUCCESS

    # Phase 2: one atomic commit for the entire group.
    try:
        commit_plan(plan, running_as_root=running_as_root)
    except CommitAborted as exc:
        for reason in exc.reasons:
            click.echo(reason, err=True)
        click.echo(
            "Placement aborted and any partial changes were rolled back: every target "
            "is back as it was.",
            err=True,
        )
        return ExitCode.UNEXPECTED_ERROR

    # Only after the group landed do we report outcomes to the platform.
    for user_plan in plan.users:
        for notice in user_plan.notices:
            click.echo(f"[{user_plan.target.username}] {notice}", err=True)
        _confirm_all(client, user_plan)
        final.fs_failure |= _summarize(user_plan)

    if final.fs_failure:
        return ExitCode.UNEXPECTED_ERROR
    return ExitCode.SUCCESS


def _confirm_all(client: EndpointDeploymentsClient, user_plan: UserPlan) -> None:
    """Report outcomes for every staged deployment. A failed confirm is logged, not
    fatal — the next reconcile re-syncs; the atomic commit already guarantees the
    on-disk state itself."""
    for entry in user_plan.entries:
        if entry.blocked:
            # Blocked entries never reach this point (the run aborts before commit),
            # but keep the guard explicit.
            continue
        if entry.deployment.action is DeploymentAction.DELETE:
            # All three remove outcomes mean the revoked decoy no longer occupies its
            # entry on disk (see the backend's verify-before-remove), including a
            # foreign entry reusing our name.
            status = ConfirmStatus.REMOVED
        else:
            status = ConfirmStatus.PLANTED
        try:
            client.confirm(entry.deployment.id, status)
        except EndpointDeploymentsError as exc:
            click.echo(
                f"[{user_plan.target.username}] could not confirm deployment "
                f"{entry.deployment.id} as {status.value}: {exc}",
                err=True,
            )


def _summarize(user_plan: UserPlan) -> bool:
    """Print the same per-user reconciliation summary as before. Returns whether any
    non-fatal filesystem problem remains (kept for exit-code aggregation)."""
    written = sum(1 for entry in user_plan.entries if entry.status is PlanStatus.WRITE)
    skipped = sum(
        1 for entry in user_plan.entries if entry.status is PlanStatus.ALREADY_CURRENT
    )
    removed = sum(
        1
        for entry in user_plan.entries
        if entry.status
        in (PlanStatus.REMOVE, PlanStatus.ALREADY_ABSENT, PlanStatus.FOREIGN_KEPT)
    )
    suffix = (
        f" (remove-only: {user_plan.suppressed_writes} planting action(s) skipped)"
        if user_plan.suppressed_writes
        else ""
    )
    for entry in user_plan.entries:
        if entry.status is PlanStatus.FOREIGN_KEPT:
            click.echo(
                f"[{user_plan.target.username}] deployment {entry.deployment.id}: "
                "entry holds a different token, left untouched",
                err=True,
            )
    click.echo(
        f"[{user_plan.target.username}] reconciled — {written} written, {skipped} "
        f"skipped, {removed} removed{suffix}"
    )
    return False
