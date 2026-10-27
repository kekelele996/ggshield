import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import MutableMapping
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple

import click
import tomlkit
from pygitguardian.models import HealthCheckResponse
from tomlkit.exceptions import TOMLKitError


if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.dirs import get_user_home_dir
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import pluralize

from .agents import AGENTS, Agent


@dataclass
class InstallationStats:
    added: int = 0
    already_present: int = 0
    # Slots repointed away from a live binary. They count in `added`, yet the
    # command they held scans every prompt: see `are_hooks_installed_globally`.
    repointed_live: int = 0
    command: str = ""


@dataclass
class BuildConfigResult:
    agent: Agent
    settings_path: Path
    new_config: MutableMapping[str, Any]
    stats: InstallationStats


@dataclass
class StagedInstall:
    """One settings file, validated and rendered in memory, not yet written.

    ``agents`` can hold more than one agent: Copilot CLI and VSCode configure
    the same global hooks file, so their templates are merged into one staged
    write instead of being installed as two targets that each read and rewrite
    the same file.
    """

    agents: List[Agent]
    settings_path: Path
    new_config: MutableMapping[str, Any]
    rendered: str
    stats_by_agent: Dict[str, InstallationStats]

    def stats_for(self, agent: Agent) -> InstallationStats:
        return self.stats_by_agent[agent.name]


@dataclass
class HookTargetFailure:
    """A settings target that could not be staged or written.

    It names both the assistant(s) and the exact settings file, which is what a
    batch run must report instead of dying on the first bad file and leaving the
    user to diff every assistant's settings by hand.
    """

    display_names: str
    settings_path: Path
    reason: str


class HookCommitError(RuntimeError):
    """A staged file could not be written, and every other file was restored."""

    def __init__(self, agents: Sequence[Agent], settings_path: Path, reason: str):
        self.agents = list(agents)
        self.settings_path = settings_path
        self.reason = reason
        super().__init__(f"{settings_path}: {reason}")


_HOOK_ARGS = "secret scan ai-hook"


def build_hook_command() -> str:
    """Build the AI hook command line written into the agent's settings.

    Pin the hook to the absolute path of the ggshield that is running
    ``install``, rather than a bare ``ggshield``. The hook runs as an
    agent-spawned process whose PATH is neither the user's shell PATH nor stable
    across launch contexts (a terminal-launched agent and a GUI-launched one can
    see different PATHs). On a machine with more than one ggshield install (e.g.
    Homebrew plus an MDM-managed copy on macOS), a bare command can resolve to a
    *different* binary than the one the user authenticated with, which then fails
    to read the stored token.

    How the path is recovered depends on the launch:

    - Frozen standalone bundle (``.pkg``/``.deb``/``.rpm``): ``sys.executable``.
      PyInstaller derives it from the OS, so under the Rust dispatcher it names
      the internal ``ggshield-py`` launcher.
    - Bare name (``ggshield``, the pip/pipx/Homebrew case): the shell does not
      absolutize ``sys.argv[0]``, so resolve it against PATH with
      ``shutil.which``.
    - Explicit or relative path (``/opt/homebrew/bin/ggshield``,
      ``./ggshield``): ``abspath``.

    Whatever comes out, a sibling ``ggshield`` dispatcher wins over it — see
    :func:`_prefer_dispatcher_sibling`.

    Symlinks are left unresolved in the code paths that see them: the
    pip/pipx/Homebrew cases go through ``shutil.which``/``abspath``, which do not
    follow the final symlink, so a stable ``…/bin/ggshield`` launcher keeps
    working across upgrades.

    The frozen path is the one place where a symlink is already gone: the OS
    resolves ``sys.executable`` for PyInstaller, and on the macOS bundle it
    resolves into a *versioned* ``/opt/gitguardian/ggshield-<version>/``
    directory that the next upgrade deletes. A stable launcher
    (``/usr/local/bin/ggshield``, ``/usr/bin/ggshield``) is therefore preferred
    when it resolves to that same binary, so the hook survives upgrades.
    """
    return f"{_quote_executable(hook_executable())} {_HOOK_ARGS}"


def hook_executable() -> str:
    """The ggshield binary the hook should run. See `build_hook_command`."""
    frozen = getattr(sys, "frozen", False)
    if frozen:
        executable = sys.executable
    else:
        argv0 = sys.argv[0]
        if os.path.dirname(argv0):
            executable = os.path.abspath(argv0)
        else:
            # On a PATH miss fall back to abspath, never sys.executable
            # (the Python interpreter, not ggshield).
            executable = shutil.which(argv0) or os.path.abspath(argv0)
    executable = _prefer_dispatcher_sibling(executable)
    # The stable launcher points at the dispatcher, so it can only match once
    # the sibling preference has run. Only the frozen path needs it: elsewhere
    # the path never went through a symlink resolution.
    return _stable_launcher(executable) if frozen else executable


def _prefer_dispatcher_sibling(executable: str) -> str:
    """Return the Rust ``ggshield`` dispatcher next to ``executable``, if any.

    Every install that ships the dispatcher puts it next to the Python entry
    point, under the two names ``ggshield`` and ``ggshield-py``: the standalone
    bundles (where PyInstaller's ``sys.executable`` is the ``ggshield-py``
    launcher) and the platform wheels (where ``ggshield`` execs ``ggshield-py``,
    so by the time Python runs, ``sys.argv[0]`` is ``ggshield-py`` too). Writing
    that Python path into the hook works, but pays the whole Python startup on
    every agent tool call — the one cost the dispatcher exists to remove.

    Installs with no dispatcher (pure wheel, older bundles) keep ``executable``:
    there, it already *is* ``ggshield``.
    """
    dispatcher = os.path.join(
        os.path.dirname(executable),
        "ggshield" + (".exe" if os.name == "nt" else ""),
    )
    if os.path.normpath(dispatcher) != os.path.normpath(executable) and os.access(
        dispatcher, os.X_OK
    ):
        return dispatcher
    return executable


def _stable_launcher(executable: str) -> str:
    """A version-independent launcher for `executable`, or `executable` itself.

    Substitution requires the launcher to resolve to the very same file: on a
    machine carrying several ggshield installs (Homebrew alongside the bundle),
    the other one is a binary the user never authenticated. A launcher that does
    not exist resolves to itself, so the comparison simply fails.
    """
    if os.name == "nt":
        return executable
    target = os.path.realpath(executable)
    for launcher in ("/usr/local/bin/ggshield", "/usr/bin/ggshield"):
        if os.path.realpath(launcher) == target:
            return launcher
    return executable


def _hook_command_executable(command: str) -> Optional[str]:
    """The ggshield path in a hook command, or None when the command is not ours.

    Anything carrying extra arguments is the user's own command, not one we wrote.
    """
    suffix = f" {_HOOK_ARGS}"
    if not command.endswith(suffix):
        return None
    windows = os.name == "nt"
    try:
        # posix=False keeps Windows path separators, which posix mode would eat
        # as escapes; it also keeps the quotes, hence the strip below.
        parts = shlex.split(command[: -len(suffix)], posix=not windows)
    except ValueError:
        # Unbalanced quote in a hand-edited command: not one of ours.
        return None
    if len(parts) != 1:
        return None
    return parts[0].strip('"') if windows else parts[0]


def _is_outdated_hook_command(existing: str, command: str) -> bool:
    """Whether an installed hook command should be repointed at `command`.

    True for a ggshield command whose binary is gone (a versioned bundle
    directory an upgrade removed) or that reaches the same binary through a less
    stable path. Anything else belongs to the user and is left alone.
    """
    if existing == command:
        return False
    installed = _hook_command_executable(existing)
    new = _hook_command_executable(command)
    if installed is None or new is None:
        return False
    if "ggshield" not in os.path.basename(installed):
        return False
    return not os.path.exists(installed) or os.path.realpath(
        installed
    ) == os.path.realpath(new)


def _quote_executable(path: str) -> str:
    """Quote an executable path for use in a shell-run hook command string."""
    if os.name == "nt":
        # Agents run the command through a shell; quote only when needed to
        # avoid disturbing parsers that don't expect quoting.
        return f'"{path}"' if " " in path else path
    return shlex.quote(path)


def install_hooks(
    name: str, mode: Literal["local", "global"], force: bool = False
) -> int:
    """Install the hooks for the AI hook.

    Args:
        name: Name of the AI coding tool
        mode: Mode of the hook installation
        force: Whether to force the installation

    Returns an error code (0 on success, 1 on failure)
    """
    try:
        agent = AGENTS[name]
    except KeyError:
        raise ValueError(f"Unsupported agent: {name}")

    # Stage (read, parse, merge, render, writability check) before the file is
    # touched, then commit through the same all-or-nothing writer the batch
    # uses: a crash or an I/O error can no longer leave a truncated settings
    # file behind.
    try:
        staged = _stage_agents([agent], mode, force)
        commit_staged_installs([staged])
    except HookCommitError as exc:
        raise UnexpectedError(
            f"Failed to write {exc.settings_path}: {exc.reason}. "
            "The original settings were left unchanged."
        ) from exc

    _report_install_result(agent, staged.settings_path, staged.stats_for(agent), mode)
    return 0


def _report_install_result(
    agent: Agent,
    settings_path: Path,
    stats: InstallationStats,
    mode: Literal["local", "global"],
) -> None:
    """Print what an install did for one assistant, plus its reload warning."""
    display_name = agent.display_name
    styled_path = click.style(settings_path, fg="yellow", bold=True)
    if stats.added == 0 and stats.already_present > 0:
        click.echo(f"{display_name} hooks already installed in {styled_path}")
    elif stats.added > 0 and stats.already_present > 0:
        click.echo(f"{display_name} hooks updated in {styled_path}")
    else:
        click.echo(f"{display_name} hooks successfully added in {styled_path}")

    if warning := agent.post_install_warning(mode):
        ui.display_warning(warning)


def _render_settings(
    agent: Agent, config: MutableMapping[str, Any], settings_path: Path
) -> str:
    """Serialize the merged config in the assistant's native format.

    Rendering is part of the staging, not the write: a document we cannot
    serialize must abort the run like an unparseable input, instead of writing a
    file the assistant cannot load.
    """
    try:
        if agent.settings_format == "toml":
            return tomlkit.dumps(config)
        return json.dumps(config, indent=2) + "\n"
    except (TOMLKitError, TypeError, ValueError) as exc:
        raise UnexpectedError(
            f"Failed to serialize the updated settings for {settings_path}: "
            f"{exc}. Please fix or remove the file before installing hooks."
        ) from exc


def _assert_target_writable(settings_path: Path) -> None:
    """Check that the settings file can be (re)created and written, touching nothing.

    The check is best effort: root bypasses permission bits and an ACL can
    change between this check and the commit, so the commit phase still backs
    every file up and rolls back. Its job is to fail BEFORE the first file of
    the batch has been replaced.
    """
    if settings_path.exists():
        if not settings_path.is_file():
            raise PermissionError(f"{settings_path} exists and is not a file")
        if not os.access(settings_path, os.W_OK):
            raise PermissionError(f"{settings_path} is not writable")
    ancestor = settings_path.parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if not ancestor.is_dir() or not os.access(ancestor, os.W_OK | os.X_OK):
        raise PermissionError(
            f"cannot create {settings_path}: {ancestor} is not a writable directory"
        )


def _stage_agents(
    agents: Sequence[Agent],
    mode: Literal["local", "global"],
    force: bool = False,
) -> StagedInstall:
    """Validate, merge and render the hooks for agents sharing one settings file.

    Only reads: nothing is created, truncated or written. Parse and shape
    failures come out as :class:`UnexpectedError` (see
    :func:`build_hook_config`), I/O failures as :class:`OSError`; both carry
    the settings path so the batch can name the failing target.
    """
    first = agents[0]
    result = build_hook_config(first.name, mode, force)
    config = result.new_config
    stats_by_agent = {first.name: result.stats}

    command = build_hook_command()
    for agent in agents[1:]:
        # Same settings file: merge each agent's template into the one document,
        # with per-agent stats so the report says "added"/"already installed"
        # independently even though the write is shared.
        agent_stats = InstallationStats()
        _fill_dict(
            config=config,
            template=agent.settings_template,
            command=command,
            overwrite=force,
            stats=agent_stats,
            locator=agent.settings_locate,
        )
        stats_by_agent[agent.name] = agent_stats

    rendered = _render_settings(first, config, result.settings_path)
    _assert_target_writable(result.settings_path)
    return StagedInstall(
        agents=list(agents),
        settings_path=result.settings_path,
        new_config=config,
        rendered=rendered,
        stats_by_agent=stats_by_agent,
    )


@dataclass
class _PreparedFile:
    """A staged file sitting in a same-directory temp file, ready to rename."""

    staged: StagedInstall
    settings_path: Path
    existed: bool
    mode: int
    tmp_path: Optional[Path]
    backup_path: Optional[Path]


def _default_file_mode() -> int:
    """Mode a newly created settings file gets, honoring the process umask."""
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def _prepare_one(staged: StagedInstall, created_dirs: List[Path]) -> _PreparedFile:
    """Create parent dirs, back up an existing file, and stage the temp file.

    Nothing is renamed in place here: any failure leaves the settings file
    exactly as it was.
    """
    settings_path = staged.settings_path
    parent = settings_path.parent

    missing_dirs: List[Path] = []
    ancestor = parent
    while not ancestor.exists():
        missing_dirs.append(ancestor)
        ancestor = ancestor.parent
    for directory in reversed(missing_dirs):
        directory.mkdir(exist_ok=True)
        created_dirs.append(directory)

    existed = settings_path.exists()
    mode = os.stat(settings_path).st_mode & 0o7777 if existed else _default_file_mode()

    backup_path: Optional[Path] = None
    if existed:
        # Same directory: the backup and the final file stay on one filesystem,
        # which is what makes the restore rename atomic too.
        backup_fd, backup_name = tempfile.mkstemp(
            prefix=f".{settings_path.name}.ggshield-backup-", dir=parent
        )
        os.close(backup_fd)
        backup_path = Path(backup_name)
        shutil.copyfile(settings_path, backup_path)

    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{settings_path.name}.ggshield-tmp-", dir=parent
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            f.write(staged.rendered)
            f.flush()
            os.fsync(f.fileno())
        # mkstemp creates the temp file 0600; give it the original file's mode
        # (or the umask-default one) before it takes the settings file's place.
        os.chmod(tmp_name, mode)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise

    return _PreparedFile(
        staged=staged,
        settings_path=settings_path,
        existed=existed,
        mode=mode,
        tmp_path=Path(tmp_name),
        backup_path=backup_path,
    )


def _unlink_quietly(path: Optional[Path]) -> None:
    if path is not None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _restore(
    prepared: Sequence[_PreparedFile],
    replaced: Sequence[_PreparedFile],
    created_dirs: Sequence[Path],
) -> None:
    """Put the settings files back the way they were before the commit.

    Replaced files get their byte-exact backup renamed back (or are deleted if
    they did not exist); the others only need their temp and backup removed.
    """
    replaced_ids = {id(item) for item in replaced}
    for item in prepared:
        if id(item) in replaced_ids:
            try:
                if item.existed and item.backup_path is not None:
                    os.replace(item.backup_path, item.settings_path)
                    try:
                        os.chmod(item.settings_path, item.mode)
                    except OSError:
                        pass
                else:
                    item.settings_path.unlink(missing_ok=True)
            except OSError:
                # Keep going: restoring the remaining files matters more than
                # surfacing an error that would hide the original failure.
                pass
        else:
            _unlink_quietly(item.tmp_path)
            _unlink_quietly(item.backup_path)

    # Only directories we created, leaves first: rmdir fails on non-empty ones,
    # which is the correct signal to leave a directory that gained other files.
    for directory in reversed(created_dirs):
        try:
            directory.rmdir()
        except OSError:
            pass


def commit_staged_installs(staged_installs: Sequence[StagedInstall]) -> None:
    """Write every staged settings file, all or nothing.

    Two phases:

    1. prepare: create missing parent directories, back up every existing file
       byte-for-byte, and write the new content to a same-directory temp file.
       A failure here has replaced nothing.
    2. commit: rename the temp files into place one by one (a same-directory
       rename is atomic). If one fails, the renames already done are rolled
       back from the backups and brand-new files are deleted.

    Raises :class:`HookCommitError` only once the disk is back to its
    pre-call state.
    """
    created_dirs: List[Path] = []
    prepared: List[_PreparedFile] = []
    replaced: List[_PreparedFile] = []
    current: Optional[StagedInstall] = None
    try:
        for staged in staged_installs:
            current = staged
            prepared.append(_prepare_one(staged, created_dirs))

        for item in prepared:
            current = item.staged
            assert item.tmp_path is not None
            os.replace(item.tmp_path, item.settings_path)
            replaced.append(item)

        # Every rename succeeded: the byte backups have no more role and must
        # not linger next to the settings files.
        for item in prepared:
            _unlink_quietly(item.backup_path)
    except OSError as exc:
        assert current is not None
        _restore(prepared, replaced, created_dirs)
        raise HookCommitError(current.agents, current.settings_path, str(exc)) from exc


def build_hook_config(
    name: str, mode: Literal["local", "global"], force: bool = False
) -> BuildConfigResult:
    """Build the hook configuration for the AI hook.

    Args:
        name: Name of the AI coding tool
        mode: Mode of the hook installation

    Returns the updated hook configuration and statistics
    """

    try:
        agent = AGENTS[name]
    except KeyError:
        raise ValueError(f"Unsupported agent: {name}")

    base_dir = get_user_home_dir() if mode == "global" else Path(".")
    settings_path = base_dir / agent.settings_path(mode)

    command = build_hook_command()

    # Load existing config or create new one
    existing_config: MutableMapping[str, Any] = (
        tomlkit.document() if agent.settings_format == "toml" else {}
    )

    if settings_path.exists():
        try:
            with settings_path.open("r", encoding="utf-8") as f:
                if agent.settings_format == "toml":
                    raw_config = f.read()
                    # Two parsers on purpose, don't drop either one:
                    # - tomllib validates. tomlkit silently *repairs* some
                    #   malformed input ("[[hooks]" becomes "[[hooks]]"), so on
                    #   its own it would rewrite a broken file into a different
                    #   one instead of telling the user to fix it.
                    # - tomlkit then builds the editable document, because it is
                    #   the only one of the two that can write back, and it keeps
                    #   the comments and formatting of a file the user hand-edits.
                    tomllib.loads(raw_config)
                    existing_config = tomlkit.parse(raw_config)
                else:
                    existing_config = json.load(f)
        # TOMLKitError, not just its ParseError subclass: a duplicate key in an
        # inline table raises KeyAlreadyPresent, which is not a ParseError.
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, TOMLKitError) as e:
            raise UnexpectedError(
                f"Failed to parse {settings_path}: {e}. "
                "Please fix or remove the file before installing hooks."
            )

    # Track what we did for reporting
    stats = InstallationStats(
        added=0,
        already_present=0,
        command="",
    )

    try:
        stats = _fill_dict(
            config=existing_config,
            template=agent.settings_template,
            command=command,
            overwrite=force,
            stats=stats,
            locator=agent.settings_locate,
        )
    except ValueError as e:
        # The file parsed but does not have the shape we can merge into.
        raise UnexpectedError(
            f"Failed to update {settings_path}: {e}. "
            "Please fix or remove the file before installing hooks."
        )

    return BuildConfigResult(
        agent=agent,
        settings_path=settings_path,
        new_config=existing_config,
        stats=stats,
    )


def _fill_dict(
    config: MutableMapping[str, Any],
    template: Dict[str, Any],
    command: str,
    overwrite: bool,
    stats: InstallationStats,
    locator: Callable[[List[Dict[str, Any]], Dict[str, Any]], Optional[Dict[str, Any]]],
) -> InstallationStats:
    """
    Recursively fill a dictionary with the template, leaving other keys untouched.

    Inside lists, `locator` finds the object to update, otherwise a new element is
    added. A template list may hold several objects: each is located independently,
    so an agent can declare more than one hook in the same list.

    Args:
        config: The dictionary to fill
        template: The template to use
        command: The command to use
        overwrite: Whether to overwrite existing keys
        stats: The statistics to update
    """
    for key, value in template.items():
        # Dictionary: recurse
        if isinstance(value, dict):
            new_config = config.setdefault(key, {})
            _fill_dict(new_config, value, command, overwrite, stats, locator)
        # List: locate the correct object
        elif isinstance(value, list):
            config_list = config.setdefault(key, [])
            if not isinstance(config_list, list):
                raise ValueError(f"expected a list of objects at '{key}'")
            for template_item in value:
                if not isinstance(template_item, dict):
                    raise ValueError(f"Expected objects in template list for {key}")
                # Re-read the candidates for every template item: an object
                # appended earlier in this same loop must be locatable, or two
                # template items that match the same slot would each append
                # their own copy -- and a re-run would grow a second ggshield
                # entry next to the first one. Ignore anything that isn't an
                # object: the file is hand-editable and a stray scalar must not
                # crash the install.
                candidates = [item for item in config_list if isinstance(item, dict)]
                existing_value = locator(candidates, template_item)
                if existing_value is not None:
                    # Found it. Continue with this object.
                    _fill_dict(
                        existing_value,
                        template_item,
                        command,
                        overwrite,
                        stats,
                        locator,
                    )
                else:
                    # Not found. Add a new object.
                    config_list.append(deepcopy(template_item))
                    _fill_dict(
                        config_list[-1],
                        template_item,
                        command,
                        overwrite,
                        stats,
                        locator,
                    )

        # Scalar value: if template is the string "<COMMAND>", replace it with the command.
        else:
            if key not in config:
                config[key] = value
            # For stats: only the command slot tells us whether ggshield is already
            # installed. Other scalars may legitimately contain "ggshield" — a hook
            # name, for instance — and must not be counted as an existing install.
            cmd = config.get(key, "")
            if value == "<COMMAND>" and isinstance(cmd, str) and "ggshield" in cmd:
                stats.already_present += 1
                stats.command = cmd
                # An upgrade invalidates a versioned bundle path, and the hook
                # then fails open: every prompt goes unscanned.
                if _is_outdated_hook_command(cmd, command):
                    config[key] = "<COMMAND>"
                    installed = _hook_command_executable(cmd)
                    if installed and os.path.exists(installed):
                        stats.repointed_live += 1
            # Update if needed
            if overwrite:
                config[key] = value
            if config[key] == "<COMMAND>":
                config[key] = command
                stats.added += 1

    return stats


def are_hooks_installed_globally(agent_name: str) -> Tuple[bool, Optional[str]]:
    """Whether the ggshield AI hooks are installed in this agent's global settings file.

    A slot repointed at a stabler path holds a hook that scans every prompt, so it
    reads as installed; only a missing or dead command leaves the agent
    unprotected. The command comes back either way, to tell a dead path from a
    config that never had a hook.
    """
    stats = build_hook_config(agent_name, "global").stats
    return stats.added == stats.repointed_live, stats.command or None


@dataclass
class AgentHookStatus:
    """Whether the ggshield AI hook is installed for one detected assistant."""

    display_name: str
    installed: bool


def ai_hook_posture() -> List[AgentHookStatus]:
    """Read-only AI-hook status: for each detected assistant, is the hook installed?

    Only assistants present on this machine are reported; it never writes anything.
    Used by ``ggshield machine doctor``.
    """
    statuses = []
    for agent in AGENTS.values():
        if agent.is_present():
            installed, _command = are_hooks_installed_globally(agent.name)
            statuses.append(
                AgentHookStatus(display_name=agent.display_name, installed=installed)
            )
    return statuses


@dataclass
class SetupSummary:
    """Outcome of configuring AI hooks across one or more agents."""

    configured: int = 0
    failed: int = 0
    # Every target that could not be staged or written, with the assistant name
    # and settings path. Empty on success.
    failures: List[HookTargetFailure] = field(default_factory=list)


def select_agents(only: Sequence[str], exclude: Sequence[str]) -> List[Agent]:
    """Pick which agents ``machine setup`` should configure.

    With no flags, returns every agent detected on this machine. ``only``
    restricts to an explicit list (configured even when not yet present, since
    the user named them). ``exclude`` drops agents from the detected set.
    """
    if only:
        return [AGENTS[name] for name in only]
    agents = [agent for agent in AGENTS.values() if agent.is_present()]
    if exclude:
        excluded = set(exclude)
        agents = [agent for agent in agents if agent.name not in excluded]
    return agents


def _group_agents_by_settings(
    agents: Sequence[Agent], mode: Literal["local", "global"]
) -> List[Tuple[Path, List[Agent]]]:
    """Group agents by their settings file path, preserving the agents' order.

    Two agents can target the same file (Copilot CLI and VSCode both configure
    ``~/.copilot/hooks/hooks.json``). Installing them as separate targets would
    build twice from the same original content -- and report one failure twice.
    They become one staged write into which both templates are merged.
    """
    base_dir = get_user_home_dir() if mode == "global" else Path(".")
    groups: Dict[str, List[Agent]] = {}
    paths: Dict[str, Path] = {}
    ordered_keys: List[str] = []
    for agent in agents:
        settings_path = base_dir / agent.settings_path(mode)
        key = str(settings_path)
        if key not in groups:
            groups[key] = []
            paths[key] = settings_path
            ordered_keys.append(key)
        groups[key].append(agent)
    return [(paths[key], groups[key]) for key in ordered_keys]


def _display_names(agents: Sequence[Agent]) -> str:
    return ", ".join(agent.display_name for agent in agents)


def _report_staging_failures(failures: Sequence[HookTargetFailure]) -> None:
    """Name every assistant/settings pair that blocked the run.

    Staging failed, so by construction no file was written: say so explicitly,
    because the previous behavior left earlier assistants' files modified and
    the user had to discover and restore them by hand.
    """
    ui.display_error(
        f"AI hooks could not be installed for {len(failures)} "
        f"{pluralize('assistant', len(failures))}. No settings file was changed. "
        "Fix or remove the listed file(s) and re-run:"
    )
    for failure in failures:
        ui.display_error(
            f"  {failure.display_names} ({failure.settings_path}): {failure.reason}"
        )


def install_all_agent_hooks(
    only: Sequence[str] = (),
    exclude: Sequence[str] = (),
    force: bool = False,
) -> SetupSummary:
    """Install the ggshield AI hook for every selected agent (user/global scope).

    This is the engine behind ``ggshield machine setup``: one command that
    configures all detected AI coding assistants instead of one per agent.

    The batch is all-or-nothing: every settings file is first read, parsed,
    merged and rendered in memory (staging), and each target is checked for
    writability. Only when all targets stage cleanly are they committed
    together, each through an atomic temp-file rename. If staging fails for any
    target, nothing is written and every failing assistant and settings file is
    reported; if a write fails despite the checks, the files already written are
    restored to their previous bytes. Re-running is therefore safe: it finds the
    hook it previously wrote and never adds a second copy.
    """
    agents = select_agents(only, exclude)
    if not agents:
        click.echo(
            "No AI coding assistants detected on this machine. "
            "Use --only <assistant> to configure one explicitly "
            f"({', '.join(sorted(AGENTS))})."
        )
        return SetupSummary()

    click.echo(
        f"Configuring ggshield AI hooks for {len(agents)} "
        f"{pluralize('assistant', len(agents))}: "
        + ", ".join(agent.display_name for agent in agents)
    )

    # Phase 1: stage every target. A failure here is a report, not an abort:
    # collect all of them so one run names every file the user must fix.
    staged_installs: List[StagedInstall] = []
    failures: List[HookTargetFailure] = []
    for settings_path, group in _group_agents_by_settings(agents, "global"):
        names = _display_names(group)
        try:
            staged_installs.append(_stage_agents(group, "global", force))
        except UnexpectedError as exc:
            # The message already carries the path and the fix.
            failures.append(HookTargetFailure(names, settings_path, str(exc)))
        except OSError as exc:
            failures.append(
                HookTargetFailure(
                    names, settings_path, f"could not access the settings: {exc}"
                )
            )

    if failures:
        _report_staging_failures(failures)
        return SetupSummary(configured=0, failed=len(failures), failures=failures)

    # Phase 2: commit all targets. A failure here has already been rolled back
    # by the time commit_staged_installs raises.
    try:
        commit_staged_installs(staged_installs)
    except HookCommitError as exc:
        names = _display_names(exc.agents)
        failure = HookTargetFailure(names, exc.settings_path, exc.reason)
        ui.display_error(
            f"Failed to write the settings for {names} ({exc.settings_path}): "
            f"{exc.reason}. Every other settings file was restored to its "
            "previous state, so no AI hook configuration changed."
        )
        return SetupSummary(configured=0, failed=1, failures=[failure])

    for staged in staged_installs:
        for agent in staged.agents:
            _report_install_result(
                agent,
                staged.settings_path,
                staged.stats_for(agent),
                "global",
            )

    configured = sum(len(staged.agents) for staged in staged_installs)
    return SetupSummary(configured=configured, failed=0)


def _is_interactive() -> bool:
    """Whether setup is running with a user present at a terminal."""
    return sys.stdout.isatty()


def check_ai_hook_authentication(config: Config) -> None:
    """Verify the freshly configured AI hook will be able to authenticate.

    The hook runs as an agent-spawned, non-interactive process, where an auth
    failure would otherwise only show up as a warning on every tool call.
    Checking now also makes the OS credentials store ask for access (e.g. the
    macOS Keychain authorization prompt) while the user can still answer it.

    Skip this in non-interactive runs (CI, automated fleet/MDM provisioning):
    there is no one to answer a credential-store popup or read the result, and
    triggering the prompt there would be disruptive.
    """
    if not _is_interactive():
        return
    try:
        client = create_client_from_config(config)
        response = client.health_check()
        if not isinstance(response, HealthCheckResponse) or response.status_code != 200:
            raise UnexpectedError(str(getattr(response, "detail", response)))
    except Exception as exc:
        ui.display_warning(
            f"The hook is installed but ggshield cannot reach GitGuardian: {exc}\n"
            "The hook will NOT scan anything until this is fixed. Run "
            "'ggshield auth login' to authenticate, then 'ggshield api-status' "
            "to check."
        )
    else:
        click.echo("ggshield successfully authenticated: the hook is ready to scan.")
    _warm_hook_credential_store()


# An event the hook answers by scanning the prompt and nothing else: no file is
# named, so it reads its token, asks the API about this one line, and exits.
_WARM_UP_EVENT = json.dumps(
    {
        "hook_event_name": "UserPromptSubmit",
        "session_id": "ggshield-machine-setup",
        "transcript_path": "ggshield-machine-setup/claude-code.jsonl",
        "prompt": "ggshield setup: checking the AI hook can read its token.",
    }
)


def _warm_hook_credential_store() -> None:
    """Have the hook binary itself read the token once, with the user present.

    Keychain ACLs are per code identity, and in the standalone bundle the hook is
    the Rust dispatcher, not the ``ggshield-py`` process running setup: the
    authentication check grants nothing to the binary that does the reading. Its
    own authorization dialog would first appear inside an agent-spawned hook,
    where the agent's timeout can kill the process before an answered "Always
    Allow" is recorded, so the dialog comes back on every turn.

    Only macOS grants per binary, and only the bundle runs the hook from another
    binary: everywhere else the token has already been read by the identity the
    hook will use.
    """
    if sys.platform != "darwin" or not getattr(sys, "frozen", False):
        return
    executable = hook_executable()
    if executable == sys.executable:
        return
    try:
        subprocess.run(
            [executable, "secret", "scan", "ai-hook"],
            input=_WARM_UP_EVENT,
            text=True,
            capture_output=True,
            # Room to answer a Keychain dialog, and a bound so setup cannot hang
            # on one nobody answers.
            timeout=60,
            check=False,
        )
    except Exception:
        pass
