"""
Configuration provenance tracing.

This module reconstructs, for each configuration key, the whole precedence
ladder ggshield resolves a value from:

    default < global config file < local config file < .env file
    < environment variable < command line option

(and the credential store / auth config file for API keys).

Unlike the regular Config loader, it keeps *every* layer's value instead of
returning only the winner, so overridden values and conflicting settings can
be displayed by `ggshield config trace`.

Sensitive values (API keys/tokens) are masked before being returned: the
credential store itself is never read.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ggshield.core.config.token_store import KEYRING_SENTINEL, get_token_store
from ggshield.core.config.user_config import (
    CURRENT_CONFIG_VERSION,
    _fix_ignore_known_secrets,
)
from ggshield.core.config.utils import (
    find_global_config_path,
    find_local_config_path,
    get_auth_config_filepath,
    load_yaml_dict,
    remove_url_trailing_slash,
    replace_dash_in_keys,
)
from ggshield.core.config.v1_config import convert_v1_config_dict
from ggshield.core.constants import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_HMSL_URL,
    DEFAULT_INSTANCE_URL,
)
from ggshield.core.filter import censor_string
from ggshield.core.url_utils import api_to_dashboard_url
from ggshield.utils.os import getenv_bool


class LayerName(str, Enum):
    """A configuration layer, ordered from lowest to highest precedence."""

    DEFAULT = "default"
    GLOBAL_CONFIG = "global config"
    LOCAL_CONFIG = "local config"
    CUSTOM_CONFIG = "custom config"
    AUTH_CONFIG = "auth config"
    KEYRING = "keyring"
    DOTENV = ".env file"
    ENV_VAR = "environment variable"
    CMD_OPTION = "command line option"


# Status of one layer value for a given key.
STATUS_ACTIVE = "active"
STATUS_OVERRIDDEN = "overridden"
STATUS_REDUNDANT = "redundant"
STATUS_MERGED = "merged"
STATUS_INVALID = "invalid"

NOT_SET = "not set"


@dataclass
class LayerValue:
    """The value a single layer provides for a configuration key."""

    layer: LayerName
    # Human-readable location within the layer: a file path, "$ENV_VAR",
    # "--cli-flag" or an instance URL.
    detail: Optional[str]
    # Already formatted for display; sensitive values are masked.
    value: Any
    status: str = STATUS_ACTIVE

    def as_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer.value,
            "detail": self.detail,
            "value": self.value,
            "status": self.status,
        }


@dataclass
class ConfigKeyTrace:
    """The full provenance information for one configuration key."""

    key: str
    # The effective value, already formatted for display.
    value: Any
    layers: List[LayerValue] = field(default_factory=list)
    sensitive: bool = False
    # True for keys whose file values are combined (sets are unioned, lists
    # appended) instead of overriding each other.
    merge: bool = False
    write_advice: str = ""

    @property
    def source(self) -> Optional[LayerValue]:
        """The layer the effective value comes from."""
        for layer_value in self.layers:
            if layer_value.status == STATUS_ACTIVE:
                return layer_value
        return None

    @property
    def conflict(self) -> bool:
        """True if at least one user-provided lower layer provides a different
        value that gets overridden, or an invalid value is ignored. A value
        differing only from the built-in default is not a conflict."""
        return any(
            layer_value.status in (STATUS_OVERRIDDEN, STATUS_INVALID)
            and layer_value.layer != LayerName.DEFAULT
            for layer_value in self.layers
        )

    def as_dict(self) -> Dict[str, Any]:
        source = self.source
        return {
            "key": self.key,
            "value": self.value,
            "sensitive": self.sensitive,
            "source": source.as_dict() if source else None,
            "conflict": self.conflict,
            "merge": self.merge,
            "layers": [layer_value.as_dict() for layer_value in self.layers],
            "write_advice": self.write_advice,
        }


@dataclass
class _FileLayer:
    name: LayerName
    path: Path
    data: Dict[str, Any]


def _silently_load_config_dict(config_path: Path) -> Optional[Dict[str, Any]]:
    """Load and normalize a YAML config file without displaying warnings.

    Mirrors user_config._load_config_dict() but discards deprecation messages
    instead of emitting them, so tracing does not replay the warnings already
    shown when the Config was loaded.
    """
    dct = load_yaml_dict(config_path)
    if dct is None:
        return None

    replace_dash_in_keys(dct)

    config_version = dct.pop("version", None)
    if config_version is None:
        config_version = 1
    if config_version == CURRENT_CONFIG_VERSION:
        _fix_ignore_known_secrets(dct)
        # The deprecated `allow_self_signed` key is equivalent to `insecure`.
        if "insecure" not in dct and "allow_self_signed" in dct:
            dct["insecure"] = dct["allow_self_signed"]
    else:
        try:
            dct = convert_v1_config_dict(dct, [])
        except Exception:
            return None
    return dct


def _dig(data: Dict[str, Any], dotted_key: str) -> Tuple[bool, Any]:
    """Look up a dotted key in a nested dict. Returns (found, value)."""
    current: Any = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _display(value: Any) -> Any:
    """Normalize a value for display/JSON serialization."""
    if value is None:
        return NOT_SET
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    return value


def _mask(value: str) -> str:
    return censor_string(value)


class _ProvenanceBuilder:
    def __init__(
        self,
        config: Any,
        cli_params: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.config = config
        self.cli_params = cli_params or {}
        self.file_layers = self._load_file_layers()
        self.dotenv_path = self._find_dotenv_path()

    def _load_file_layers(self) -> List[_FileLayer]:
        custom_path = self.cli_params.get("config_path")
        if custom_path is not None:
            path = Path(custom_path)
            data = _silently_load_config_dict(path)
            if data is not None:
                return [_FileLayer(LayerName.CUSTOM_CONFIG, path, data)]
            return []

        layers: List[_FileLayer] = []
        global_path = find_global_config_path()
        if global_path is not None:
            data = _silently_load_config_dict(global_path)
            if data is not None:
                layers.append(_FileLayer(LayerName.GLOBAL_CONFIG, global_path, data))
        local_path = find_local_config_path()
        if local_path is not None:
            data = _silently_load_config_dict(local_path)
            if data is not None:
                layers.append(_FileLayer(LayerName.LOCAL_CONFIG, local_path, data))
        return layers

    def _find_dotenv_path(self) -> Optional[Path]:
        """Path of the .env file that was loaded, if its variables are
        referenced, None otherwise."""
        if not self.config._dotenv_vars:
            return None
        # Imported here to keep the env discovery logic in one place.
        from ggshield.core.env_utils import _find_dot_env

        try:
            return _find_dot_env()
        except Exception:
            return None

    # -- env helpers -------------------------------------------------------

    def _env_layer(self, var_name: str) -> Optional[LayerValue]:
        """The env var layer (plain environment or .env file) defining
        var_name, if any."""
        if var_name not in os.environ:
            return None
        if var_name in self.config._dotenv_vars and self.dotenv_path is not None:
            return LayerValue(
                LayerName.DOTENV,
                f"{self.dotenv_path} (${var_name})",
                os.environ[var_name],
            )
        return LayerValue(LayerName.ENV_VAR, f"${var_name}", os.environ[var_name])

    # -- finalization ------------------------------------------------------

    @staticmethod
    def _finalize_scalar(
        key: str,
        candidates: List[LayerValue],
        *,
        default_value: Any,
        sensitive: bool = False,
        advice: str = "",
    ) -> ConfigKeyTrace:
        """Pick the last candidate as the winner and mark the others.

        Candidate values are expected to be already formatted for display
        (sensitive values must be masked by the caller).
        """
        ordered = [
            LayerValue(
                candidate.layer,
                candidate.detail,
                _display(candidate.value),
                candidate.status,
            )
            for candidate in candidates
        ]
        if not ordered:
            ordered = [LayerValue(LayerName.DEFAULT, None, _display(default_value))]

        valid = [
            candidate for candidate in ordered if candidate.status != STATUS_INVALID
        ]
        winner = valid[-1]
        final_value = winner.value
        for candidate in ordered:
            if candidate is winner:
                candidate.status = STATUS_ACTIVE
            elif candidate.status == STATUS_INVALID:
                continue
            elif candidate.value == final_value:
                candidate.status = STATUS_REDUNDANT
            else:
                candidate.status = STATUS_OVERRIDDEN

        return ConfigKeyTrace(
            key=key,
            value=final_value,
            layers=ordered,
            sensitive=sensitive,
            write_advice=advice,
        )

    def _file_advice(
        self,
        dotted_key: str,
        *,
        winner: Optional[LayerValue],
        file_winner: Optional[LayerValue] = None,
        per_repo: bool = True,
    ) -> str:
        """Build the "where should I write this" advice for a file-backed
        key, deliberately scoped to one key so unrelated settings are not
        copied around."""
        blocker_note = ""
        if winner is not None:
            if winner.layer == LayerName.ENV_VAR:
                blocker_note = (
                    f"Editing a config file has no effect until you unset"
                    f" {winner.detail}. "
                )
            elif winner.layer == LayerName.DOTENV:
                blocker_note = (
                    f"Editing a config file has no effect until you remove"
                    f" {winner.detail} from the .env file. "
                )
            elif winner.layer == LayerName.CMD_OPTION:
                blocker_note = (
                    f"Editing a config file has no effect for invocations that"
                    f" pass {winner.detail}. "
                )

        if "." in dotted_key:
            section, leaf = dotted_key.split(".", 1)
            snippet = f"`{section}:` with `{leaf}: <value>` under it"
        else:
            snippet = f"`{dotted_key}: <value>`"

        custom = any(
            layer.name == LayerName.CUSTOM_CONFIG for layer in self.file_layers
        )
        global_path = find_global_config_path(to_write=True)
        # The file ggshield itself writes to: the local config (the default
        # local path when none exists) or the --config-path file.
        local_path = self.config.config_path

        if blocker_note:
            target = (
                file_winner.detail
                if file_winner is not None
                else (str(local_path) if per_repo and not custom else str(global_path))
            )
            if custom:
                target = str(local_path)
            return (
                f"{blocker_note}To persist a value, set only {snippet} in"
                f" {target}; do not copy the other settings from higher layers."
            )

        if file_winner is not None:
            return (
                f"Edit only {snippet} in {file_winner.detail}; the other"
                " settings in that file do not need to be changed or copied."
            )

        if custom:
            return (
                f"Add only {snippet} to the custom config file {local_path};"
                " do not copy the other settings from higher layers."
            )
        if per_repo:
            return (
                f"Add only {snippet} to the local config file {local_path} to"
                f" apply to this repository; use the global config file"
                f" {global_path} instead to apply it to every repository. Do not"
                " copy the other settings from higher layers."
            )
        return (
            f"Add only {snippet} to the global config file {global_path}; do"
            " not copy the other settings from higher layers."
        )

    # -- generic file scalar keys -----------------------------------------

    def _trace_file_scalar(
        self,
        key: str,
        default_value: Any,
        *,
        env_var: Optional[str] = None,
        cli_flag: Optional[str] = None,
        value_type: type = str,
        per_repo: bool = True,
    ) -> ConfigKeyTrace:
        candidates: List[LayerValue] = [
            LayerValue(LayerName.DEFAULT, None, default_value)
        ]

        file_winner: Optional[LayerValue] = None
        for file_layer in self.file_layers:
            found, raw_value = _dig(file_layer.data, key)
            if found:
                file_winner = LayerValue(
                    file_layer.name, str(file_layer.path), raw_value
                )
                candidates.append(file_winner)

        env_winner: Optional[LayerValue] = None
        invalid_note = ""
        if env_var is not None:
            env_layer = self._env_layer(env_var)
            if env_layer is not None:
                if value_type is bool:
                    env_layer.value = getenv_bool(env_var, default=False)
                    candidates.append(env_layer)
                    env_winner = env_layer
                elif value_type is int:
                    raw_value = os.environ[env_var]
                    try:
                        env_layer.value = int(raw_value)
                    except ValueError:
                        env_layer.status = STATUS_INVALID
                        candidates.append(env_layer)
                        invalid_note = (
                            f"${env_var} has invalid value {raw_value!r};"
                            " expected an integer, fix or unset it. "
                        )
                    else:
                        candidates.append(env_layer)
                        env_winner = env_layer
                else:
                    candidates.append(env_layer)
                    env_winner = env_layer

        cli_winner: Optional[LayerValue] = None
        if cli_flag is not None:
            param_name = cli_flag.lstrip("-").replace("-", "_")
            if self.cli_params.get(param_name):
                cli_winner = LayerValue(LayerName.CMD_OPTION, cli_flag, True)
                candidates.append(cli_winner)

        winner = cli_winner or env_winner
        advice = invalid_note + self._file_advice(
            key, winner=winner, file_winner=file_winner, per_repo=per_repo
        )
        return self._finalize_scalar(
            key,
            candidates,
            default_value=default_value,
            advice=advice,
        )

    # -- instance ----------------------------------------------------------

    def _trace_instance(self) -> ConfigKeyTrace:
        key = "instance"
        candidates: List[LayerValue] = [
            LayerValue(LayerName.DEFAULT, None, DEFAULT_INSTANCE_URL)
        ]

        for file_layer in self.file_layers:
            found, raw_value = _dig(file_layer.data, key)
            if found and raw_value:
                candidates.append(
                    LayerValue(file_layer.name, str(file_layer.path), raw_value)
                )

        env_winner = None
        # GITGUARDIAN_API_URL has lower priority than GITGUARDIAN_INSTANCE.
        for var_name in ("GITGUARDIAN_API_URL", "GITGUARDIAN_INSTANCE"):
            env_layer = self._env_layer(var_name)
            if env_layer is None:
                continue
            if var_name == "GITGUARDIAN_API_URL":
                env_layer.value = api_to_dashboard_url(os.environ[var_name])
            else:
                env_layer.value = remove_url_trailing_slash(os.environ[var_name])
            candidates.append(env_layer)
            env_winner = env_layer

        cli_winner = None
        if self.config._cmdline_instance_name:
            cli_winner = LayerValue(
                LayerName.CMD_OPTION,
                "--instance",
                self.config._cmdline_instance_name,
            )
            candidates.append(cli_winner)

        # Reuse the production resolution as the source of truth for the
        # effective value.
        final_value, _ = self.config.get_instance_name_and_source()
        advice = self._instance_advice(cli_winner or env_winner)
        trace = self._finalize_scalar(
            key,
            candidates,
            default_value=DEFAULT_INSTANCE_URL,
            advice=advice,
        )
        trace.value = final_value
        if trace.source is not None:
            trace.source.value = final_value
        return trace

    def _instance_advice(self, winner: Optional[LayerValue]) -> str:
        if winner is not None:
            if winner.layer == LayerName.CMD_OPTION:
                blocker = "drop the --instance option"
            elif winner.detail and "($" in winner.detail:
                blocker = f"remove {winner.detail}"
            elif winner.detail and winner.detail.startswith("$"):
                blocker = f"unset {winner.detail}"
            else:
                blocker = f"remove the instance setting from {winner.detail}"
            return (
                f"The instance is forced for this invocation ({blocker}). To make"
                " a persistent change, run `ggshield config set instance <url>`,"
                " which writes only this key to the global config file."
            )
        return (
            "Run `ggshield config set instance <url>` to change it persistently:"
            " it writes only this key to the global config file"
            f" ({find_global_config_path(to_write=True)}). Use --instance or"
            " $GITGUARDIAN_INSTANCE for a one-off override."
        )

    # -- api key -----------------------------------------------------------

    def _trace_api_key(self) -> ConfigKeyTrace:
        key = "api_key"
        instance_name = self.config.instance_name
        candidates: List[LayerValue] = []

        # Lower layer: token stored for the selected instance. The credential
        # store is never read (it can pop a Keychain prompt); a keyring token
        # is reported as such.
        try:
            instance_config = self.config.auth_config.get_instance(instance_name)
        except Exception:
            instance_config = None
        if instance_config is not None and instance_config.account is not None:
            raw_token = instance_config.account.token
            if raw_token == KEYRING_SENTINEL:
                if get_token_store().uses_external_storage:
                    candidates.append(
                        LayerValue(
                            LayerName.KEYRING, instance_name, "stored in keyring"
                        )
                    )
                else:
                    candidates.append(
                        LayerValue(
                            LayerName.AUTH_CONFIG,
                            str(get_auth_config_filepath()),
                            "not available (keyring disabled)",
                        )
                    )
            elif raw_token:
                candidates.append(
                    LayerValue(
                        LayerName.AUTH_CONFIG,
                        str(get_auth_config_filepath()),
                        _mask(raw_token),
                    )
                )

        env_winner = self._env_layer("GITGUARDIAN_API_KEY")
        if env_winner is not None:
            env_winner.value = _mask(os.environ["GITGUARDIAN_API_KEY"])
            candidates.append(env_winner)

        if candidates:
            trace = self._finalize_scalar(
                key, candidates, default_value=NOT_SET, sensitive=True
            )
        else:
            trace = ConfigKeyTrace(
                key=key,
                value=NOT_SET,
                layers=[LayerValue(LayerName.DEFAULT, None, NOT_SET, STATUS_ACTIVE)],
                sensitive=True,
            )

        if env_winner is not None:
            env_detail = env_winner.detail
            trace.write_advice = (
                f"{env_detail} currently overrides the stored credential; unset"
                " it (or remove it from the .env file) to use the stored one, or"
                f" run `ggshield auth login --instance {instance_name}` to replace"
                " the stored token."
            )
        else:
            trace.write_advice = (
                "Change it with `ggshield auth login"
                f" --instance {instance_name}`: the token is written only to the"
                " credential store/auth config, never paste it into a YAML config"
                " file."
            )
        return trace

    # -- merge keys (sets/lists) ------------------------------------------

    def _trace_merged_set(self, dotted_key: str) -> ConfigKeyTrace:
        candidates: List[LayerValue] = []
        combined: set = set()
        for file_layer in self.file_layers:
            found, raw_value = _dig(file_layer.data, dotted_key)
            if found and raw_value:
                raw_set = set(raw_value)
                combined |= raw_set
                candidates.append(
                    LayerValue(
                        file_layer.name,
                        str(file_layer.path),
                        sorted(raw_set),
                        STATUS_MERGED,
                    )
                )
        final_value = sorted(combined)
        return ConfigKeyTrace(
            key=dotted_key,
            value=final_value,
            layers=candidates,
            merge=True,
            write_advice=self._merge_advice(dotted_key),
        )

    def _merge_advice(self, dotted_key: str) -> str:
        target = self.config.config_path
        custom = any(
            layer.name == LayerName.CUSTOM_CONFIG for layer in self.file_layers
        )
        section, leaf = dotted_key.split(".", 1)
        if custom:
            where = f"the custom config file {target}"
        else:
            where = (
                f"the local config file {target} (or the global config file"
                f" {find_global_config_path(to_write=True)} for all repositories)"
            )
        return (
            "Values from the global and local files are combined, not overridden."
            f" Add only the new entry under `{section}:` -> `{leaf}:` in {where};"
            " do not copy the entries already defined in the other file."
        )

    # -- endpoint registration --------------------------------------------

    def _trace_endpoint_registration(self) -> ConfigKeyTrace:
        key = "endpoint_registration"
        candidates: List[LayerValue] = [LayerValue(LayerName.DEFAULT, None, True)]
        file_winner = None
        for file_layer in self.file_layers:
            found, raw_value = _dig(file_layer.data, key)
            if found:
                file_winner = LayerValue(
                    file_layer.name, str(file_layer.path), raw_value
                )
                candidates.append(file_winner)

        env_winner = None
        # Any non-empty value opts out, mirroring machine_id.py.
        if os.getenv("GGSHIELD_NO_ENDPOINT_REGISTRATION"):
            env_winner = LayerValue(
                LayerName.ENV_VAR,
                "$GGSHIELD_NO_ENDPOINT_REGISTRATION",
                False,
            )
            candidates.append(env_winner)

        advice = self._file_advice(
            key, winner=env_winner, file_winner=file_winner, per_repo=False
        )
        return self._finalize_scalar(key, candidates, default_value=True, advice=advice)

    # -- default_token_lifetime (auth config) ------------------------------

    def _trace_default_token_lifetime(self) -> ConfigKeyTrace:
        key = "default_token_lifetime"
        auth_path = str(get_auth_config_filepath())
        default_value = self.config.auth_config.default_token_lifetime
        candidates = [
            LayerValue(LayerName.AUTH_CONFIG, auth_path, _display(default_value))
        ]
        instance_name = self.config.instance_name
        instance_value: Any = None
        try:
            instance_config = self.config.auth_config.get_instance(instance_name)
        except Exception:
            instance_config = None
        if instance_config is not None:
            instance_value = instance_config.default_token_lifetime
            if instance_value is not None:
                candidates.append(
                    LayerValue(
                        LayerName.AUTH_CONFIG,
                        f"{auth_path} [{instance_name}]",
                        instance_value,
                    )
                )

        trace = self._finalize_scalar(key, candidates, default_value=NOT_SET)
        instance_part = (
            f" --instance {instance_name}" if instance_value is not None else ""
        )
        trace.write_advice = (
            "Change it with `ggshield config set default_token_lifetime <days>"
            f"{instance_part}`; only this key is written to {auth_path}."
        )
        return trace

    # -- hmsl url -----------------------------------------------------------

    def _trace_hmsl_url(self) -> ConfigKeyTrace:
        key = "hmsl_url"
        candidates = [LayerValue(LayerName.DEFAULT, None, DEFAULT_HMSL_URL)]
        env_layer = self._env_layer("GITGUARDIAN_HMSL_URL")
        if env_layer is not None:
            env_layer.value = remove_url_trailing_slash(
                os.environ["GITGUARDIAN_HMSL_URL"]
            )
            candidates.append(env_layer)
            advice = (
                f"The HMSL URL is forced by {env_layer.detail}; unset it to use"
                " the default. This setting can only be set through the"
                " environment, there is no config-file key."
            )
        else:
            advice = (
                "Set $GITGUARDIAN_HMSL_URL to override it; there is no"
                " config-file key for this setting."
            )
        return self._finalize_scalar(
            key, candidates, default_value=DEFAULT_HMSL_URL, advice=advice
        )

    # -- entry point --------------------------------------------------------

    def build(self) -> List[ConfigKeyTrace]:
        traces: List[ConfigKeyTrace] = []

        # Connection settings: bespoke precedence chains.
        traces.append(self._trace_instance())
        traces.append(self._trace_api_key())
        traces.append(
            self._trace_file_scalar(
                "api_timeout",
                DEFAULT_API_TIMEOUT,
                env_var="GITGUARDIAN_API_TIMEOUT",
                value_type=int,
                per_repo=False,
            )
        )

        # Generic file/env/cli scalars.
        traces.append(
            self._trace_file_scalar(
                "exit_zero",
                False,
                env_var="GITGUARDIAN_EXIT_ZERO",
                value_type=bool,
            )
        )
        cli_flag = (
            "--allow-self-signed"
            if self.cli_params.get("allow_self_signed")
            else "--insecure"
        )
        traces.append(self._trace_file_scalar("insecure", False, cli_flag=cli_flag))
        traces.append(self._trace_file_scalar("verbose", False, cli_flag="--verbose"))
        traces.append(self._trace_file_scalar("debug", False, cli_flag="--debug"))
        traces.append(self._trace_endpoint_registration())
        traces.append(
            self._trace_file_scalar(
                "max_commits_for_hook",
                50,
                env_var="GITGUARDIAN_MAX_COMMITS_FOR_HOOK",
                value_type=int,
            )
        )
        traces.append(self._trace_hmsl_url())
        traces.append(self._trace_default_token_lifetime())

        # Secret-specific scalar settings: file layers only.
        for secret_key, default_value in (
            ("secret.show_secrets", False),
            ("secret.ignore_known_secrets", False),
            ("secret.with_incident_details", False),
            ("secret.all_secrets", False),
            ("secret.fail_on_server_error", True),
            ("secret.filename_only", False),
            ("secret.prereceive_remediation_message", ""),
        ):
            traces.append(
                self._trace_file_scalar(
                    secret_key,
                    default_value,
                    value_type=str if isinstance(default_value, str) else bool,
                )
            )

        # Secret-specific set settings: global + local are merged.
        traces.append(self._trace_merged_set("secret.ignored_detectors"))
        traces.append(self._trace_merged_set("secret.ignored_paths"))

        return traces


def trace_config(
    config: Any,
    cli_params: Optional[Dict[str, Any]] = None,
) -> List[ConfigKeyTrace]:
    """Return provenance information for every traced configuration key.

    `cli_params` is the Click root context params dict, used to detect
    command-line overrides (--insecure, --verbose, --debug, --config-path...).
    """
    return _ProvenanceBuilder(config, cli_params).build()


TRACEABLE_KEYS = [
    "instance",
    "api_key",
    "api_timeout",
    "exit_zero",
    "insecure",
    "verbose",
    "debug",
    "endpoint_registration",
    "max_commits_for_hook",
    "hmsl_url",
    "default_token_lifetime",
    "secret.show_secrets",
    "secret.ignore_known_secrets",
    "secret.with_incident_details",
    "secret.all_secrets",
    "secret.fail_on_server_error",
    "secret.filename_only",
    "secret.prereceive_remediation_message",
    "secret.ignored_detectors",
    "secret.ignored_paths",
]
