"""
Two-phase, all-or-nothing placement for ``ggshield honeytoken plant``.

The old loop applied deployments one by one, so discovering halfway through that a
file had been hand-edited (or now held someone else's identity) left the earlier files
already changed — recovery meant restoring backups. This module splits placement into:

1. **Plan** (:func:`build_user_plan` / :class:`Plan`): every deployment of every target
   user is resolved and *staged* against the current on-disk text with zero writes.
   Each entry gets a verdict — write, identical (already planted), remove, already
   absent, foreign-entry-kept, or **blocked** (a collision/malformed file/bad payload)
   — together with the account/profile or cluster/context identity it belongs to, and
   the other identities sharing the file. Any blocked entry aborts the whole run, so a
   single conflict never lands a partial group.
2. **Commit** (:func:`commit_plan`): once the plan is confirmed, every involved
   directory is locked, each file is re-read and compared to the planned snapshot
   (catching a change made *after* the plan was shown), and only then are all staged
   contents published. A publish/fix-up failure rolls every already-published file back
   to its exact pre-run bytes, so the group is either fully applied or byte-for-byte
   untouched.

Entries that are already current stage no change, so re-running the command never
places a second copy.

The per-format decisions themselves live in the backends (``aws_profile``,
``kubeconfig_file``); this module owns sequencing, identity labeling, the transaction,
and the read-only rendering.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ggshield.verticals.honeytoken import secure_file
from ggshield.verticals.honeytoken.aws_profile import (
    resolve_placement,
    stage_aws_remove,
    stage_aws_write,
    summarize_aws,
)
from ggshield.verticals.honeytoken.endpoint_deployments import (
    Deployment,
    DeploymentAction,
    DeploymentMethod,
    HoneytokenCreds,
    KubeconfigToken,
)
from ggshield.verticals.honeytoken.kubeconfig_file import (
    kube_identity,
    kube_path,
    stage_kubeconfig_remove,
    stage_kubeconfig_write,
    summarize_kubeconfig,
)
from ggshield.verticals.honeytoken.placement import (
    ForceRefusal,
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
)
from ggshield.verticals.honeytoken.secure_file import SecureFileError
from ggshield.verticals.honeytoken.targets import Target, ownership_for


# --- plan data --------------------------------------------------------------------


class PlanStatus(enum.Enum):
    """The read-only verdict for one deployment, shown by the plan and mapped back to
    the confirm status after a successful commit."""

    WRITE = "write"
    ALREADY_CURRENT = "already-current"
    REMOVE = "remove"
    ALREADY_ABSENT = "already-absent"
    FOREIGN_KEPT = "foreign-kept"
    BLOCKED = "blocked"


_STATUS_LABEL = {
    PlanStatus.WRITE: "write",
    PlanStatus.ALREADY_CURRENT: "identical, already planted",
    PlanStatus.REMOVE: "remove",
    PlanStatus.ALREADY_ABSENT: "already absent",
    PlanStatus.FOREIGN_KEPT: "foreign entry present, kept",
    PlanStatus.BLOCKED: "BLOCKED",
}


@dataclass
class EntryIdentity:
    """Who a deployment belongs to — the label the user reviews before confirming.

    ``kind`` is ``aws-profile`` (an account profile) or ``kubeconfig-context`` (a
    cluster); ``name`` is the profile/context name and ``details`` carry non-secret
    identifiers (access key *id*, cluster server, user name) — never the secret key or
    bearer.
    """

    kind: str
    name: str
    title: str
    details: Tuple[str, ...] = ()


@dataclass
class PlannedEntry:
    target: Target
    deployment: Deployment
    path: Path
    status: PlanStatus
    identity: Optional[EntryIdentity]
    problem: Optional[str] = None

    @property
    def blocked(self) -> bool:
        return self.status is PlanStatus.BLOCKED


@dataclass
class StagedFile:
    """One concrete file's planned end state, after sequencing every deployment that
    touches it (e.g. a rotation's delete-then-write collapses into a single result)."""

    target: Target
    path: Path
    # Exact text read while planning (None = the file did not exist); the commit
    # re-verifies against this before publishing.
    baseline: Optional[str]
    # Desired text (None = the file must be unlinked).
    desired: Optional[str]
    owner: Optional[secure_file.Ownership]

    @property
    def changed(self) -> bool:
        return self.baseline != self.desired


@dataclass
class UserPlan:
    target: Target
    entries: List[PlannedEntry] = field(default_factory=list)
    files: Dict[Path, StagedFile] = field(default_factory=dict)
    # Write deployments skipped in --remove-only mode (for the summary suffix).
    suppressed_writes: int = 0
    # Forward-compat: actions a newer backend introduced (logged, not applied).
    notices: List[str] = field(default_factory=list)

    def entries_for(self, path: Path) -> List[PlannedEntry]:
        return [entry for entry in self.entries if entry.path == path]


@dataclass
class Plan:
    users: List[UserPlan] = field(default_factory=list)

    @property
    def all_entries(self) -> List[PlannedEntry]:
        return [entry for user in self.users for entry in user.entries]

    @property
    def blocked_entries(self) -> List[PlannedEntry]:
        return [entry for entry in self.all_entries if entry.blocked]

    @property
    def has_blockers(self) -> bool:
        return bool(self.blocked_entries)

    @property
    def has_changes(self) -> bool:
        return any(
            staged.changed for user in self.users for staged in user.files.values()
        )

    def count(self, status: PlanStatus) -> int:
        return sum(1 for entry in self.all_entries if entry.status is status)

    @property
    def written(self) -> int:
        return self.count(PlanStatus.WRITE)

    @property
    def skipped(self) -> int:
        return self.count(PlanStatus.ALREADY_CURRENT)

    @property
    def removed(self) -> int:
        return (
            self.count(PlanStatus.REMOVE)
            + self.count(PlanStatus.ALREADY_ABSENT)
            + self.count(PlanStatus.FOREIGN_KEPT)
        )


# --- read-only planning -----------------------------------------------------------


def _read_current(path: Path) -> Optional[str]:
    """Read a placement file the same hardened way the backends do (no-follow,
    fd-anchored, locked, size-capped), without creating anything. A symlinked dir/file
    or other unsafe read surfaces as :class:`PlacementError`; absent means None."""
    secure_file.require_safe_backend()
    if secure_file.FD_HARDENED:
        try:
            dir_fd = secure_file.open_dir_fd(path.parent, create=False)
        except FileNotFoundError:
            return None
        try:
            return secure_file.read_via_fd(dir_fd, path.name)
        finally:
            os.close(dir_fd)
    secure_file.reject_symlinked_target(path)
    return secure_file.read_path(path)


def _aws_identity(
    deployment: Deployment, token: Optional[HoneytokenCreds]
) -> EntryIdentity:
    profile = deployment.config.profile_name
    details = (f"access key id {token.access_token_id}",) if token is not None else ()
    return EntryIdentity(
        kind="aws-profile",
        name=profile,
        title=f"aws profile [{profile}]",
        details=details,
    )


def _kube_entry_identity(ident: object) -> EntryIdentity:
    """Turn the backend's parsed kubeconfig identity into the plan label."""
    details = [f"cluster [{ident.cluster_name}]"]
    if ident.server:
        details[-1] += f" ({ident.server})"
    details.append(f"user [{ident.user_name}]")
    return EntryIdentity(
        kind="kubeconfig-context",
        name=ident.context_name,
        title=f"kubeconfig context [{ident.context_name}]",
        details=tuple(details),
    )


def _fallback_kube_identity(token: Optional[KubeconfigToken]) -> EntryIdentity:
    name = token.context_name if token is not None else "?"
    return EntryIdentity(
        kind="kubeconfig-context",
        name=name,
        title=f"kubeconfig context [{name}]",
    )


class _Sequencer:
    """Runs the ordered deletes-then-writes against in-memory file text, mirroring the
    on-disk apply order (a rotation frees the profile slot before its replacement is
    written). All I/O happens through here; decisions are the backends'."""

    def __init__(self, target: Target, force: bool) -> None:
        self.target = target
        self.force = force
        self._current: Dict[Path, Optional[str]] = {}
        self._baseline: Dict[Path, Optional[str]] = {}
        self.entries: List[PlannedEntry] = []

    def text_of(self, path: Path) -> Optional[str]:
        if path not in self._current:
            baseline = _read_current(path)
            self._baseline[path] = baseline
            self._current[path] = baseline
        return self._current[path]

    def baseline_of(self, path: Path) -> Optional[str]:
        return self._baseline[path]

    def record(
        self,
        deployment: Deployment,
        path: Path,
        status: PlanStatus,
        identity: Optional[EntryIdentity],
        *,
        problem: Optional[str] = None,
    ) -> None:
        self.entries.append(
            PlannedEntry(
                target=self.target,
                deployment=deployment,
                path=path,
                status=status,
                identity=identity,
                problem=problem,
            )
        )

    def stage(self, deployment: Deployment) -> None:
        """Stage one deployment: validate payload, decide, render — or record a blocker.
        A blocker never mutates the file's staged state."""
        item_path = self._path_for(deployment)
        try:
            if deployment.action is DeploymentAction.WRITE:
                identity, status, desired = self._stage_write(deployment, item_path)
            else:
                identity, status, desired = self._stage_remove(deployment, item_path)
        except (PlacementError, ForceRefusal) as exc:
            # A foreign same-named entry (ForceRefusal), an unparseable/unsafe file, or a
            # bad payload blocks the whole group instead of clobbering anything.
            self.record(
                deployment,
                item_path,
                PlanStatus.BLOCKED,
                self._identity_best_effort(deployment),
                problem=str(exc),
            )
            return
        if status in (PlanStatus.WRITE, PlanStatus.REMOVE):
            self._current[item_path] = desired
        self.record(deployment, item_path, status, identity)

    # -- per-method dispatch --------------------------------------------------------

    def _path_for(self, deployment: Deployment) -> Path:
        if deployment.method in (
            DeploymentMethod.AWS_CREDENTIALS,
            DeploymentMethod.AWS_CONFIG_PROFILE,
        ):
            path, _section = resolve_placement(
                deployment.method, deployment.config, self.target.home
            )
            return path
        if deployment.method is DeploymentMethod.KUBECONFIG:
            return kube_path(self.target.home, deployment.config.filename)
        # Unknown method has no safe path; anchor the blocker on the home so the plan
        # still has somewhere to print it.
        return self.target.home

    @staticmethod
    def _aws_section(deployment: Deployment) -> str:
        """The INI section an AWS deployment lands in (the config-file ``profile ``
        prefix is the only difference between the two AWS methods)."""
        section = deployment.config.profile_name
        if deployment.method is DeploymentMethod.AWS_CONFIG_PROFILE:
            return f"profile {section}"
        return section

    def _identity_best_effort(self, deployment: Deployment) -> Optional[EntryIdentity]:
        token = deployment.token
        if deployment.method in (
            DeploymentMethod.AWS_CREDENTIALS,
            DeploymentMethod.AWS_CONFIG_PROFILE,
        ):
            creds = token if isinstance(token, HoneytokenCreds) else None
            return _aws_identity(deployment, creds)
        if deployment.method is DeploymentMethod.KUBECONFIG:
            kube_token = token if isinstance(token, KubeconfigToken) else None
            if kube_token is None:
                return EntryIdentity(
                    kind="kubeconfig-context",
                    name="?",
                    title="kubeconfig context [?]",
                )
            try:
                return _kube_entry_identity(kube_identity(kube_token))
            except PlacementError:
                return _fallback_kube_identity(kube_token)
        return None

    def _stage_write(
        self, deployment: Deployment, path: Path
    ) -> Tuple[EntryIdentity, PlanStatus, Optional[str]]:
        method = deployment.method
        token = deployment.token
        if method is DeploymentMethod.UNKNOWN:
            raise PlacementError(
                "unsupported deployment method — client may be out of date"
            )
        if token is None:
            raise PlacementError("'write' entry missing credentials")

        text = self.text_of(path)
        if method in (
            DeploymentMethod.AWS_CREDENTIALS,
            DeploymentMethod.AWS_CONFIG_PROFILE,
        ):
            if not isinstance(token, HoneytokenCreds):
                raise PlacementError("aws deployment is missing its credentials")
            outcome, desired = stage_aws_write(
                text, self._aws_section(deployment), token, self.force, path
            )
            identity = _aws_identity(deployment, token)
            status = (
                PlanStatus.WRITE
                if outcome is WriteOutcome.WROTE
                else PlanStatus.ALREADY_CURRENT
            )
            return identity, status, desired

        if method is DeploymentMethod.KUBECONFIG:
            if not isinstance(token, KubeconfigToken):
                raise PlacementError("kubeconfig deployment is missing its kubeconfig")
            ident, outcome, desired = stage_kubeconfig_write(
                text, token, self.force, path
            )
            status = (
                PlanStatus.WRITE
                if outcome is WriteOutcome.WROTE
                else PlanStatus.ALREADY_CURRENT
            )
            return _kube_entry_identity(ident), status, desired

        raise PlacementError(
            "unsupported deployment method — client may be out of date"
        )

    def _stage_remove(
        self, deployment: Deployment, path: Path
    ) -> Tuple[Optional[EntryIdentity], PlanStatus, Optional[str]]:
        method = deployment.method
        token = deployment.token
        if method is DeploymentMethod.UNKNOWN:
            raise PlacementError(
                "unsupported deployment method — client may be out of date"
            )

        text = self.text_of(path)
        if method in (
            DeploymentMethod.AWS_CREDENTIALS,
            DeploymentMethod.AWS_CONFIG_PROFILE,
        ):
            creds = token if isinstance(token, HoneytokenCreds) else None
            outcome, desired = stage_aws_remove(
                text,
                self._aws_section(deployment),
                creds.access_token_id if creds else None,
                path,
            )
            return _aws_identity(deployment, creds), _REMOVE_STATUS[outcome], desired

        if method is DeploymentMethod.KUBECONFIG:
            if not isinstance(token, KubeconfigToken):
                # The server always ships the identity on delete; without it there is
                # nothing safe to remove.
                raise PlacementError(
                    "kubeconfig delete is missing its kubeconfig identity"
                )
            ident, outcome, desired = stage_kubeconfig_remove(text, token, path)
            return _kube_entry_identity(ident), _REMOVE_STATUS[outcome], desired

        raise PlacementError(
            "unsupported deployment method — client may be out of date"
        )


_REMOVE_STATUS = {
    RemoveOutcome.REMOVED: PlanStatus.REMOVE,
    RemoveOutcome.ALREADY_ABSENT: PlanStatus.ALREADY_ABSENT,
    RemoveOutcome.FOREIGN_KEPT: PlanStatus.FOREIGN_KEPT,
}


def build_user_plan(
    target: Target,
    deployments: List[Deployment],
    *,
    force: bool,
    running_as_root: bool,
    remove_only: bool = False,
) -> UserPlan:
    """Stage all of one user's deployments read-only, preserving the apply order
    (deletes first so a rotation frees its slot, then writes)."""
    user_plan = UserPlan(target=target)
    owner = ownership_for(target, running_as_root)
    sequencer = _Sequencer(target, force)

    ordered: List[Deployment] = [
        item
        for item in deployments
        if item.action in (DeploymentAction.DELETE, DeploymentAction.WRITE)
    ]
    for item in deployments:
        if item.action is DeploymentAction.UNKNOWN:
            user_plan.notices.append(
                f"ignoring unknown action for deployment {item.id} "
                "— client may be out of date"
            )
    if remove_only:
        user_plan.suppressed_writes = sum(
            1 for item in deployments if item.action is DeploymentAction.WRITE
        )
        ordered = [item for item in ordered if item.action is DeploymentAction.DELETE]

    # Deletes first, then writes — same order the old on-disk loop used.
    ordered.sort(key=lambda item: item.action is not DeploymentAction.DELETE)
    for item in ordered:
        sequencer.stage(item)

    user_plan.entries = sequencer.entries
    for path, desired in sequencer._current.items():
        user_plan.files[path] = StagedFile(
            target=target,
            path=path,
            baseline=sequencer.baseline_of(path),
            desired=desired,
            owner=owner,
        )
    return user_plan


# --- plan rendering ---------------------------------------------------------------


def _companions(user_plan: UserPlan, path: Path) -> List[str]:
    """Identities the file held BEFORE this run, minus the ones our entries own — the
    "someone else's identity also lives here" line."""
    staged = user_plan.files.get(path)
    if staged is None:
        return []
    ours = {
        entry.identity.name
        for entry in user_plan.entries_for(path)
        if entry.identity is not None
    }
    if ".aws" in path.parts:
        present = summarize_aws(staged.baseline, path)
    elif ".kube" in path.parts:
        present = summarize_kubeconfig(staged.baseline, str(path))
    else:
        present = []
    return [line for line in present if not any(name in line for name in ours)]


def format_plan(plan: Plan, *, dry_run: bool) -> str:
    """Render the read-only placement plan. Names and key IDs only — no secret
    material."""
    if dry_run:
        lines = ["Placement plan (dry run; no files will be changed):"]
    else:
        lines = ["Placement plan:"]

    for user_plan in plan.users:
        target = user_plan.target
        uid = f"uid {target.uid}" if target.uid is not None else "uid -"
        lines.append("")
        lines.append(f"[{target.username}]  ({uid})  {target.home}")
        # Entries blocked before any disk read (unknown method, missing payload) never
        # make it into `files`, so render them under their own path too.
        paths = list(user_plan.files.keys()) + [
            entry.path
            for entry in user_plan.entries
            if entry.path not in user_plan.files
        ]
        if not paths:
            lines.append("  nothing to do")
        for path in paths:
            lines.append(f"  {path}")
            for entry in user_plan.entries_for(path):
                identity = entry.identity
                lines.append(
                    f"    [{_STATUS_LABEL[entry.status]}] "
                    f"{identity.title if identity else 'deployment ' + entry.deployment.id}"
                )
                if identity is not None:
                    for detail in identity.details:
                        lines.append(f"        {detail}")
                if entry.blocked and entry.problem:
                    lines.append(f"        reason: {entry.problem}")
            for companion in _companions(user_plan, path):
                lines.append(f"    file also holds: {companion}")
        for notice in user_plan.notices:
            lines.append(f"  {notice}")

    blocked = plan.blocked_entries
    if blocked:
        lines.append("")
        lines.append(f"{len(blocked)} blocking problem(s) — nothing will be written:")
        for entry in blocked:
            who = entry.target.username
            lines.append(f"  [{who}] {entry.path}: {entry.problem}")
    else:
        lines.append("")
        lines.append(
            f"Summary: {plan.written} to write, {plan.removed} to remove, "
            f"{plan.skipped} already in place"
        )
    return "\n".join(lines)


# --- atomic commit ----------------------------------------------------------------


class CommitAborted(Exception):
    """The commit was stopped before (or rolled back after) publishing; all targets
    are meant to be back at their planned baselines."""

    def __init__(self, reasons: List[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def _changed_files(plan: Plan) -> List[StagedFile]:
    return [
        staged
        for user_plan in plan.users
        for staged in user_plan.files.values()
        if staged.changed
    ]


def _publish_via_fd(staged: StagedFile, dir_fd: int) -> None:
    if staged.desired is None:
        secure_file.unlink_via_fd(dir_fd, staged.path.name)
    else:
        secure_file.atomic_write_via_fd(
            dir_fd, staged.path.name, staged.desired, staged.owner
        )


def _rollback_via_fd(
    dirs: Dict[Path, int], published: List[StagedFile], problems: List[str]
) -> None:
    """Best-effort restore of every already-published file to its planned baseline."""
    for staged in reversed(published):
        try:
            fd = dirs[staged.path.parent]
            if staged.baseline is None:
                secure_file.unlink_via_fd(fd, staged.path.name)
            else:
                secure_file.atomic_write_via_fd(
                    fd, staged.path.name, staged.baseline, staged.owner
                )
        except (SecureFileError, OSError) as exc:
            problems.append(f"additionally could not roll back {staged.path}: {exc}")


def _fixup_dirs_via_fd(
    dirs: Dict[Path, int], files: List[StagedFile], running_as_root: bool
) -> None:
    """Keep each touched placement dir private (0700) and, as root, hand it to the
    target user — on the pinned fd while the lock is held (the non-transactional helper
    would deadlock trying to re-acquire it)."""
    owner_by_dir = {staged.path.parent: staged.owner for staged in files}
    for directory, fd in dirs.items():
        try:
            os.fchmod(fd, 0o700)
        except OSError:
            pass
        if not running_as_root:
            continue
        owner = owner_by_dir.get(directory)
        if owner is None:
            continue
        try:
            uid, gid = owner.resolve(fd)
            os.fchown(fd, uid, gid)
        except OSError as exc:
            raise secure_file.SecureFileError(
                f"could not hand {directory} back to uid {uid} after writing it: {exc}"
            )


def _remove_dirs_we_created(created: List[Path]) -> None:
    """On abort, drop an empty placement directory the commit itself created (its
    home chain was already there). A directory that now holds anything is left alone:
    rmdir fails on a non-empty dir by design, so a concurrent entry can't be lost."""
    for directory in created:
        try:
            os.rmdir(directory)
        except OSError:
            pass


def _commit_via_fd(plan: Plan, *, running_as_root: bool) -> None:
    files = _changed_files(plan)
    dirs: Dict[Path, int] = {}
    created_dirs: List[Path] = []
    published: List[StagedFile] = []
    abort_problems: List[str] = []
    try:
        # Lock every involved directory before a single byte is published. Opening all
        # of them first means a failure to acquire one (e.g. a swapped symlink) aborts
        # with nothing touched.
        for staged in files:
            parent = staged.path.parent
            if parent not in dirs:
                if not parent.exists():
                    created_dirs.append(parent)
                dirs[parent] = secure_file.open_dir_fd(parent, create=True)

        # Verify the world still matches the plan: a file edited after the plan was
        # shown makes the whole commit stop before publishing anything.
        for staged in files:
            try:
                current_text = secure_file.read_via_fd(
                    dirs[staged.path.parent], staged.path.name
                )
            except SecureFileError as exc:
                abort_problems.append(f"{staged.path}: {exc}")
                continue
            if current_text != staged.baseline:
                abort_problems.append(
                    f"{staged.path}: file changed since the plan was reviewed "
                    "(edited or swapped); refusing to apply this group"
                )
        if abort_problems:
            raise CommitAborted(abort_problems)

        for staged in files:
            try:
                _publish_via_fd(staged, dirs[staged.path.parent])
            except (SecureFileError, OSError) as exc:
                abort_problems.append(f"could not write {staged.path}: {exc}")
                raise CommitAborted(abort_problems)
            published.append(staged)

        # Only re-perm/chown a directory that still holds a file. A directory whose
        # last file we unlinked pre-existed with its owner's own mode/ownership, so it
        # is not ours to widen/tighten (a directory we created always has surviving
        # content — we only create dirs for writes).
        surviving = [staged for staged in files if staged.desired is not None]
        surviving_dirs = {
            directory: dirs[directory]
            for directory in {f.path.parent for f in surviving}
        }
        try:
            _fixup_dirs_via_fd(surviving_dirs, surviving, running_as_root)
        except SecureFileError as exc:
            abort_problems.append(str(exc))
            raise CommitAborted(abort_problems)
    except CommitAborted:
        _rollback_via_fd(dirs, published, abort_problems)
        raise
    finally:
        for fd in dirs.values():
            os.close(fd)
        if abort_problems:
            _remove_dirs_we_created(created_dirs)


def _commit_via_path(plan: Plan, *, running_as_root: bool) -> None:
    """Windows-style fallback: no dir fds/locks, so the same verify-then-publish order
    applies with path ops and best-effort rollback (the dir fix-up is a POSIX no-op)."""
    files = _changed_files(plan)
    published: List[StagedFile] = []
    problems: List[str] = []
    try:
        for staged in files:
            try:
                current_text = secure_file.read_path(staged.path)
            except SecureFileError as exc:
                problems.append(f"{staged.path}: {exc}")
                continue
            if current_text != staged.baseline:
                problems.append(
                    f"{staged.path}: file changed since the plan was reviewed "
                    "(edited or swapped); refusing to apply this group"
                )
        if problems:
            raise CommitAborted(problems)

        for staged in files:
            try:
                if staged.desired is None:
                    secure_file.unlink_path(staged.path)
                else:
                    secure_file.atomic_write_path(staged.path, staged.desired)
            except (SecureFileError, OSError) as exc:
                problems.append(f"could not write {staged.path}: {exc}")
                raise CommitAborted(problems)
            published.append(staged)
    except CommitAborted:
        for staged in reversed(published):
            try:
                if staged.baseline is None:
                    secure_file.unlink_path(staged.path)
                else:
                    secure_file.atomic_write_path(staged.path, staged.baseline)
            except (SecureFileError, OSError) as exc:
                problems.append(
                    f"additionally could not roll back {staged.path}: {exc}"
                )
        raise


def commit_plan(plan: Plan, *, running_as_root: bool) -> None:
    """Publish the whole plan at once or leave every target exactly as planned.

    A blocked plan must never reach here (the caller checks :attr:`Plan.has_blockers`).
    Raises :class:`CommitAborted` when verification fails or a publish could not be
    completed (rollback attempted).
    """
    if plan.has_blockers:
        raise CommitAborted(["the plan has blocking problems; refusing to commit"])
    changed = _changed_files(plan)
    if not changed:
        return
    secure_file.require_safe_backend()
    if secure_file.FD_HARDENED:
        _commit_via_fd(plan, running_as_root=running_as_root)
    else:
        _commit_via_path(plan, running_as_root=running_as_root)
