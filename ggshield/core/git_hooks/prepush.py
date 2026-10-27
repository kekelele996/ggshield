import logging
import os
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ggshield.core import ui
from ggshield.utils.git_shell import EMPTY_SHA, git, is_valid_git_commit_ref


logger = logging.getLogger(__name__)


OUTDATED_HOOK_MESSAGE = """The installed pre-push hook did not pass its command-line arguments to ggshield. This can cause the hook to fail if the name of the remote you are pushing to is not "origin".

This can happen if the hook has been created manually or by an old version of ggshield.

To fix it, either edit the hook manually or make a backup of it and reinstall it with the following command:

    ggshield install -m local -t pre-push -f
"""  # noqa: E501

BYPASS_MESSAGE = """  - if you use the pre-commit framework:

     SKIP=ggshield-push git push

  - otherwise (warning: the following command bypasses all pre-push hooks):

     git push --no-verify"""


@dataclass(frozen=True)
class PushRef:
    """
    A single ref update sent to the pre-push hook on stdin.

    A single push can contain several of these, for example when pushing multiple
    branches or pushing to a mirror repository.
    """

    local_ref: str
    local_commit: str
    remote_ref: str
    remote_commit: str
    # Set when the information comes from the pre-commit framework environment,
    # which does not provide ref names and already resolves the range bounds.
    precommit_env: bool = False

    @property
    def is_deletion(self) -> bool:
        return self.local_commit == EMPTY_SHA

    @property
    def is_new_tree(self) -> bool:
        return self.precommit_env and self.remote_commit == EMPTY_SHA

    @property
    def name(self) -> str:
        """Human-readable name of the ref being updated."""
        ref = self.remote_ref if self.local_ref == "(delete)" else self.local_ref
        return ref or self.remote_ref or "(pushed ref)"


def find_branch_start(commit: str, remote: str) -> Optional[str]:
    """
    Returns the first local-only commit of the branch.
    Returns None if the branch does not contain any new commit.
    """
    # List all ancestors of `commit` which are not in `remote`
    # Based on _pre_push_ns() from pre-commit
    #
    # Note: The `--remotes` argument MUST be set using a `=`: `--remotes={remote}` works,
    # but `--remotes {remote}` fails.
    output = git(
        [
            "rev-list",
            commit,
            "--topo-order",
            "--reverse",
            "--not",
            f"--remotes={remote}",
        ]
    )
    ancestors = output.splitlines()

    if ancestors:
        return ancestors[0]
    return None


def parse_prepush_lines(prepush_input: str) -> List[PushRef]:
    """
    Parse all the ref updates sent to the pre-push hook.

    Each input line is expected to be:
        <local ref> SP <local sha> SP <remote ref> SP <remote sha>
    """
    push_refs: List[PushRef] = []
    for line in prepush_input.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) < 4:
            logger.warning("Ignoring malformed pre-push input line: %s", line)
            continue
        local_ref, local_commit, remote_ref, remote_commit = fields
        push_refs.append(
            PushRef(
                local_ref=local_ref,
                local_commit=local_commit,
                remote_ref=remote_ref,
                remote_commit=remote_commit,
            )
        )
    return push_refs


def collect_push_refs_from_stdin(remote_name: str) -> List[PushRef]:
    """
    Collect all the ref updates sent to the pre-push hook from stdin.
    Returns an empty list when there is nothing to push.
    """
    prepush_input = sys.stdin.read().strip()
    logger.debug("input=%s", prepush_input)
    if not prepush_input:
        # Happens when there's nothing to push
        return []

    return parse_prepush_lines(prepush_input)


def collect_commits_from_stdin(remote_name: str) -> Tuple[str, str]:
    """
    Collect pre-commit variables from stdin.

    Deprecated: use collect_push_refs_from_stdin() to handle pushes containing
    more than one ref update.
    """
    push_refs = collect_push_refs_from_stdin(remote_name)
    if not push_refs:
        return (EMPTY_SHA, EMPTY_SHA)

    push_ref = push_refs[0]
    if push_ref.local_commit == EMPTY_SHA:
        return (push_ref.local_commit, push_ref.remote_commit)

    if is_valid_git_commit_ref(push_ref.remote_commit):
        # Pushing to an existing branch
        return (push_ref.local_commit, push_ref.remote_commit)

    # Pushing to a new branch
    start_commit = find_branch_start(push_ref.local_commit, remote_name)
    if start_commit is None:
        return push_ref.local_commit, push_ref.local_commit
    return (push_ref.local_commit, f"{start_commit}~1")


def collect_commits_from_precommit_env() -> Tuple[Optional[str], Optional[str]]:
    """
    Collect from pre-commit framework environment.
    """
    # pre-commit framework <2.2.0
    local_commit = os.getenv("PRE_COMMIT_SOURCE", None)
    remote_commit = os.getenv("PRE_COMMIT_ORIGIN", None)

    if local_commit is None or remote_commit is None:
        # pre-commit framework >=2.2.0
        local_commit = os.getenv("PRE_COMMIT_FROM_REF", None)
        remote_commit = os.getenv("PRE_COMMIT_TO_REF", None)

    return (local_commit, remote_commit)


def collect_push_refs(prepush_args: List[str] = []) -> List[PushRef]:
    """
    Collect all the ref updates of the push, either from the pre-commit framework
    environment (a single update) or from the hook stdin (possibly several
    updates when pushing multiple refs at once).
    """
    local_commit, remote_commit = collect_commits_from_precommit_env()
    if local_commit is not None and remote_commit is not None:
        return [
            PushRef(
                local_ref="",
                local_commit=local_commit,
                remote_ref="",
                remote_commit=remote_commit,
                precommit_env=True,
            )
        ]

    if len(prepush_args) == 0:
        ui.display_warning(OUTDATED_HOOK_MESSAGE)
        remote_name = "origin"
    else:
        remote_name = prepush_args[0]
    return collect_push_refs_from_stdin(remote_name)


def collect_commits_refs(prepush_args: List[str] = []) -> Tuple[str, str]:
    """
    Deprecated: use collect_push_refs() to handle pushes containing more than one
    ref update.
    """
    local_commit, remote_commit = collect_commits_from_precommit_env()
    if local_commit is None or remote_commit is None:
        if len(prepush_args) == 0:
            ui.display_warning(OUTDATED_HOOK_MESSAGE)
            remote_name = "origin"
        else:
            remote_name = prepush_args[0]
        local_commit, remote_commit = collect_commits_from_stdin(remote_name)
    return (local_commit, remote_commit)
