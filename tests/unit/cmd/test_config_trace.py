import json
import os
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from ggshield.__main__ import cli
from ggshield.core.config import Config
from ggshield.core.config.token_store import KeyringTokenStore
from ggshield.core.config.utils import find_global_config_path
from ggshield.core.constants import DEFAULT_INSTANCE_URL
from ggshield.core.errors import ExitCode
from tests.unit.conftest import write_yaml

from .utils import add_instance_config


# Environment variables that can change provenance resolution. Cleared in
# every test so results do not depend on the developer's shell.
_ENV_VARS = (
    "GITGUARDIAN_API_KEY",
    "GITGUARDIAN_API_URL",
    "GITGUARDIAN_INSTANCE",
    "GITGUARDIAN_API_TIMEOUT",
    "GITGUARDIAN_EXIT_ZERO",
    "GITGUARDIAN_MAX_COMMITS_FOR_HOOK",
    "GITGUARDIAN_HMSL_URL",
    "GGSHIELD_NO_ENDPOINT_REGISTRATION",
)


@pytest.fixture(autouse=True)
def _clear_config_env(monkeypatch):
    # Variables already present are deleted through monkeypatch, which
    # restores them on teardown. Absent variables are tracked manually: a
    # .env loaded by the CLI in-process adds such vars, and pytest's
    # monkeypatch.delenv does not track absent vars, so without this they
    # would leak into later tests.
    absent_vars = []
    for name in _ENV_VARS:
        if name in os.environ:
            monkeypatch.delenv(name)
        else:
            absent_vars.append(name)
    yield
    for name in absent_vars:
        os.environ.pop(name, None)


LOCAL_CONFIG = ".gitguardian.yaml"


def _run(
    cli_fs_runner,
    *args: str,
    json_output: bool = True,
    env: Optional[Dict[str, str]] = None,
):
    cmd = list(args) + (["--json"] if json_output else [])
    cli_fs_runner.mix_stderr = False
    result = cli_fs_runner.invoke(
        cli, cmd, color=False, catch_exceptions=False, env=env
    )
    return result


def _payload(result) -> Any:
    return json.loads(result.output)


def _find(traces: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
    return next(trace for trace in traces if trace["key"] == key)


def _statuses(trace: Dict[str, Any]) -> Dict[str, str]:
    return {layer["layer"]: layer["status"] for layer in trace["layers"]}


def _layer(trace: Dict[str, Any], layer_name: str) -> Dict[str, Any]:
    return next(layer for layer in trace["layers"] if layer["layer"] == layer_name)


class TestConfigTrace:
    def test_defaults(self, cli_fs_runner):
        """
        GIVEN no config file and no override
        WHEN running `ggshield config trace --json`
        THEN every key is reported with the default as active source
        """
        result = _run(cli_fs_runner, "config", "trace")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        traces = _payload(result)

        assert {trace["key"] for trace in traces} == {
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
        }

        instance = _find(traces, "instance")
        assert instance["value"] == DEFAULT_INSTANCE_URL
        assert instance["source"]["layer"] == "default"
        assert instance["conflict"] is False

        insecure = _find(traces, "insecure")
        assert insecure["value"] is False
        assert insecure["source"]["layer"] == "default"

        # No conflict when nothing differs from a user-provided layer.
        assert all(trace["conflict"] is False for trace in traces)
        assert all(trace["write_advice"] for trace in traces)

    def test_local_file_overrides_global_conflict(self, cli_fs_runner):
        """
        GIVEN a global and a local config file defining the same key differently
        WHEN tracing the key
        THEN the local file wins, the global value is overridden and a conflict
             is reported
        """
        write_yaml(
            find_global_config_path(to_write=True),
            {"version": 2, "exit_zero": True, "instance": "https://global.example.com"},
        )
        write_yaml(
            LOCAL_CONFIG,
            {"version": 2, "exit_zero": False, "instance": "https://local.example.com"},
        )

        result = _run(cli_fs_runner, "config", "trace")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        traces = _payload(result)

        exit_zero = _find(traces, "exit_zero")
        assert exit_zero["value"] is False
        assert exit_zero["source"]["layer"] == "local config"
        assert _statuses(exit_zero)["global config"] == "overridden"
        assert exit_zero["conflict"] is True

        instance = _find(traces, "instance")
        assert instance["value"] == "https://local.example.com"
        assert instance["source"]["layer"] == "local config"
        assert _layer(instance, "global config")["status"] == "overridden"
        assert instance["conflict"] is True

    def test_same_value_in_two_files_is_redundant_not_conflict(self, cli_fs_runner):
        """
        GIVEN the same value defined in the global and local config files
        WHEN tracing the key
        THEN the local value is active, the global one is redundant and no
             conflict is reported
        """
        write_yaml(
            find_global_config_path(to_write=True),
            {"version": 2, "insecure": True},
        )
        write_yaml(LOCAL_CONFIG, {"version": 2, "insecure": True})

        result = _run(cli_fs_runner, "config", "trace", "insecure")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] is True
        assert trace["source"]["layer"] == "local config"
        statuses = _statuses(trace)
        assert statuses["global config"] == "redundant"
        assert trace["conflict"] is False

    def test_env_var_overrides_file(self, cli_fs_runner, monkeypatch):
        """
        GIVEN api_timeout set in a config file and by an environment variable
        WHEN tracing api_timeout
        THEN the env var wins, the file value is overridden and the tip tells
             the user to unset it
        """
        write_yaml(LOCAL_CONFIG, {"version": 2, "api_timeout": 30})
        monkeypatch.setenv("GITGUARDIAN_API_TIMEOUT", "45")

        result = _run(cli_fs_runner, "config", "trace", "api_timeout")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] == 45
        assert trace["source"]["layer"] == "environment variable"
        assert trace["source"]["detail"] == "$GITGUARDIAN_API_TIMEOUT"
        assert _layer(trace, "local config")["status"] == "overridden"
        assert trace["conflict"] is True
        assert "unset $GITGUARDIAN_API_TIMEOUT" in trace["write_advice"]

    def test_invalid_env_var_is_invalid_not_winner(self, cli_fs_runner, monkeypatch):
        """
        GIVEN a non-integer GITGUARDIAN_API_TIMEOUT
        WHEN tracing api_timeout
        THEN the invalid env value is flagged invalid, the config value wins and
             the conflict is reported
        """
        write_yaml(LOCAL_CONFIG, {"version": 2, "api_timeout": 30})
        monkeypatch.setenv("GITGUARDIAN_API_TIMEOUT", "not-an-int")

        result = _run(cli_fs_runner, "config", "trace", "api_timeout")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        env_layer = _layer(trace, "environment variable")
        assert env_layer["status"] == "invalid"
        assert env_layer["value"] == "not-an-int"
        assert trace["value"] == 30
        assert trace["source"]["layer"] == "local config"
        assert trace["conflict"] is True
        assert "invalid value" in trace["write_advice"]

    def test_cli_option_wins(self, cli_fs_runner):
        """
        GIVEN --insecure passed on the command line
        WHEN tracing insecure
        THEN the command line layer wins and the default is overridden without
             being reported as a conflict
        """
        result = _run(cli_fs_runner, "--insecure", "config", "trace", "insecure")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] is True
        assert trace["source"]["layer"] == "command line option"
        assert trace["source"]["detail"] == "--insecure"
        assert trace["conflict"] is False
        assert "--insecure" in trace["write_advice"]

    def test_cli_instance_wins_over_everything(self, cli_fs_runner, monkeypatch):
        """
        GIVEN instance defined in files, env and command line
        WHEN tracing instance
        THEN --instance wins and every lower layer is shown
        """
        write_yaml(
            find_global_config_path(to_write=True),
            {"version": 2, "instance": "https://global.example.com"},
        )
        write_yaml(
            LOCAL_CONFIG, {"version": 2, "instance": "https://local.example.com"}
        )
        monkeypatch.setenv("GITGUARDIAN_INSTANCE", "https://env.example.com")

        result = _run(
            cli_fs_runner,
            "--instance",
            "https://cli.example.com",
            "config",
            "trace",
            "instance",
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] == "https://cli.example.com"
        assert trace["source"]["layer"] == "command line option"
        layers = {layer["layer"]: layer for layer in trace["layers"]}
        assert layers["global config"]["status"] == "overridden"
        assert layers["local config"]["status"] == "overridden"
        assert layers["environment variable"]["status"] == "overridden"
        assert layers["environment variable"]["value"] == "https://env.example.com"
        assert trace["conflict"] is True

    def test_dotenv_layer(self, cli_fs_runner):
        """
        GIVEN a .env file defining GITGUARDIAN_INSTANCE
        WHEN tracing instance
        THEN the value is attributed to the .env file layer, not the plain
             environment
        """
        write_yaml(LOCAL_CONFIG, {"version": 2})
        with open(".env", "w") as f:
            f.write("GITGUARDIAN_INSTANCE=https://dotenv.example.com\n")

        result = _run(cli_fs_runner, "config", "trace", "instance")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] == "https://dotenv.example.com"
        assert trace["source"]["layer"] == ".env file"
        assert "GITGUARDIAN_INSTANCE" in trace["source"]["detail"]
        assert ".env" in trace["write_advice"]

    def test_ignored_paths_are_merged_not_overridden(self, cli_fs_runner):
        """
        GIVEN secret.ignored_paths defined in both config files
        WHEN tracing the key
        THEN both layers are merged into the final value with status merged
        """
        write_yaml(
            find_global_config_path(to_write=True),
            {"version": 2, "secret": {"ignored_paths": ["b-path", "a-path"]}},
        )
        write_yaml(
            LOCAL_CONFIG, {"version": 2, "secret": {"ignored_paths": ["c-path"]}}
        )

        result = _run(cli_fs_runner, "config", "trace", "secret.ignored_paths")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["merge"] is True
        assert trace["value"] == ["a-path", "b-path", "c-path"]
        assert all(layer["status"] == "merged" for layer in trace["layers"])
        assert trace["source"] is None

    def test_api_key_from_env_is_masked(self, cli_fs_runner, monkeypatch):
        """
        GIVEN GITGUARDIAN_API_KEY set to a secret value
        WHEN tracing api_key, in text and json
        THEN the raw secret never appears and a masked value is shown
        """
        secret = "0123456789abcdef0123456789abcdef0123456789"
        monkeypatch.setenv("GITGUARDIAN_API_KEY", secret)

        result = _run(cli_fs_runner, "config", "trace", "api_key")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["sensitive"] is True
        assert trace["source"]["layer"] == "environment variable"
        assert secret not in result.output
        assert trace["value"] != secret
        assert trace["value"].endswith("3456789")
        assert "*" in trace["value"]

        # Text output must hide the secret too.
        text_result = _run(
            cli_fs_runner, "config", "trace", "api_key", json_output=False
        )
        assert secret not in text_result.output

    def test_api_key_from_auth_file_is_masked(self, cli_fs_runner):
        """
        GIVEN a token stored in the auth config file for the selected instance
        WHEN tracing api_key with no env override
        THEN the file layer is the source and the token is masked
        """
        add_instance_config(token_name="trace token")

        result = _run(cli_fs_runner, "config", "trace", "api_key")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["source"]["layer"] == "auth config"
        assert trace["source"]["detail"].endswith("auth_config.yaml")
        assert trace["value"] != "some token"
        assert trace["sensitive"] is True
        assert "auth login" in trace["write_advice"]

    def test_keyring_token_is_not_read(self, cli_fs_runner, monkeypatch):
        """
        GIVEN the selected instance token lives in the credential store
        WHEN tracing api_key
        THEN the store is never read and the token is reported as stored there
        """
        add_instance_config()
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        mock_store = KeyringTokenStore()
        mock_store.get_token = MagicMock()
        mock_store.store_token = MagicMock()
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ), patch(
            "ggshield.core.config.provenance.get_token_store",
            return_value=mock_store,
        ):
            Config().save()
            result = _run(cli_fs_runner, "config", "trace", "api_key")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)
        assert trace["source"]["layer"] == "keyring"
        assert trace["value"] == "stored in keyring"
        mock_store.get_token.assert_not_called()

    def test_tip_points_to_winning_file_and_key_only(self, cli_fs_runner):
        """
        GIVEN a local config file defining several keys
        WHEN tracing one key
        THEN the tip references the local file and the single key, without
             copying the other settings
        """
        write_yaml(
            LOCAL_CONFIG,
            {
                "version": 2,
                "insecure": True,
                "exit_zero": True,
                "secret": {"show_secrets": True},
            },
        )

        result = _run(cli_fs_runner, "config", "trace", "insecure")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert LOCAL_CONFIG in trace["write_advice"]
        assert "`insecure: <value>`" in trace["write_advice"]
        assert "exit_zero" not in trace["write_advice"]
        assert "show_secrets" not in trace["write_advice"]

    def test_custom_config_path(self, cli_fs_runner):
        """
        GIVEN ggshield runs with --config-path
        WHEN tracing a key from that file
        THEN the source is the custom config layer
        """
        custom_path = "custom.yaml"
        write_yaml(
            custom_path,
            {"version": 2, "exit_zero": True, "verbose": True},
        )
        write_yaml(LOCAL_CONFIG, {"version": 2, "insecure": True})

        result = _run(
            cli_fs_runner,
            "-c",
            custom_path,
            "config",
            "trace",
            "exit_zero",
        )
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] is True
        assert trace["source"]["layer"] == "custom config"
        assert trace["source"]["detail"].endswith(custom_path)
        # The local file is ignored entirely with --config-path.
        assert all(layer["layer"] != "local config" for layer in trace["layers"])

    def test_text_output_single_key(self, cli_fs_runner):
        """
        GIVEN a text format request for one key
        WHEN running `ggshield config trace instance`
        THEN the output shows the ladder for that key and nothing about the
             other keys
        """
        result = _run(cli_fs_runner, "config", "trace", "instance", json_output=False)
        assert result.exit_code == ExitCode.SUCCESS, result.output

        assert result.output.startswith("instance\n")
        assert "final value:" in result.output
        assert "source:" in result.output
        assert "layers:" in result.output
        assert "tip:" in result.output
        assert "api_timeout" not in result.output

    def test_invalid_key_rejected(self, cli_fs_runner):
        """
        GIVEN an unknown KEY argument
        WHEN running `ggshield config trace unknown`
        THEN click rejects it with a usage error
        """
        result = _run(cli_fs_runner, "config", "trace", "unknown")
        assert result.exit_code == ExitCode.USAGE_ERROR

    def test_endpoint_registration_env_optout(self, cli_fs_runner, monkeypatch):
        """
        GIVEN GGSHIELD_NO_ENDPOINT_REGISTRATION set
        WHEN tracing endpoint_registration
        THEN the env layer wins with value false
        """
        write_yaml(LOCAL_CONFIG, {"version": 2, "endpoint_registration": True})
        monkeypatch.setenv("GGSHIELD_NO_ENDPOINT_REGISTRATION", "1")

        result = _run(cli_fs_runner, "config", "trace", "endpoint_registration")
        assert result.exit_code == ExitCode.SUCCESS, result.output
        trace = _payload(result)

        assert trace["value"] is False
        assert trace["source"]["layer"] == "environment variable"
        assert _layer(trace, "local config")["status"] == "overridden"
