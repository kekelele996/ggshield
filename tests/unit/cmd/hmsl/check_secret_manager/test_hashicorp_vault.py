from unittest.mock import Mock, patch

import pytest

from ggshield.__main__ import cli
from ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault import (
    _get_vault_token,
    _split_vault_mount_and_path,
)
from ggshield.core.errors import ExitCode
from ggshield.verticals.hmsl.collection import (
    NAMING_STRATEGIES,
    PreparedSecrets,
    SecretWithKey,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultForbiddenItemError,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultManifest,
    VaultManifestEntry,
    VaultScanResult,
)


def test_get_vault_token_from_vault_cli(monkeypatch):
    """
    GIVEN the _get_vault_token method
    WHEN getting the token from the Vault CLI
    THEN the result of the get_vault_cli_token in the vertical is used, not the one
    from env.
    """
    monkeypatch.setenv("VAULT_TOKEN", "should_not_use_token_from_env")

    token_from_cli = "cli_token"

    with patch(
        "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.get_vault_cli_token",
        return_value=token_from_cli,
    ) as get_vault_cli_token_mock:
        returned_token = _get_vault_token(use_vault_cli_token=True)

        assert returned_token == token_from_cli
        get_vault_cli_token_mock.assert_called_once()


def test_get_vault_token_from_env(monkeypatch):
    """
    GIVEN the _get_vault_token method
    WHEN getting the token from the Vault CLI
    THEN the token from the env is used, not the one from Vault cli
    """
    token_from_env = "my_env_vault_token"
    monkeypatch.setenv("VAULT_TOKEN", token_from_env)

    with patch(
        "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.get_vault_cli_token",
        return_value="should_not_use_token_from_cli",
    ) as get_vault_cli_token_mock:
        returned_token = _get_vault_token(use_vault_cli_token=False)

        assert returned_token == token_from_env
        get_vault_cli_token_mock.assert_not_called()


@pytest.mark.parametrize(
    "input_str,expected_output",
    [
        ("dev/b2b", ("dev", "b2b")),
        ("/dev/b2b/", ("dev", "b2b")),
        ("/dev/b2c", ("dev", "b2c")),
        ("dev/b2c/", ("dev", "b2c")),
        ("prod/web/app/2", ("prod", "web/app/2")),
        ("/prod/web/app/2/", ("prod", "web/app/2")),
        ("/prod/web/app/2", ("prod", "web/app/2")),
        ("prod/web/app/2/", ("prod", "web/app/2")),
    ],
)
def test_split_vault_mount_and_path(input_str, expected_output):
    """
    GIVEN a path combining mount and path
    WHEN calling _split_vault_mount_and_path
    THEN the mount and path are splitted correctly
    """

    assert _split_vault_mount_and_path(input_str) == expected_output


V2_MANIFEST = VaultManifest(
    root_path="",
    recursive=False,
    entries=[
        VaultManifestEntry(path="dev/config.env", version=1),
        VaultManifestEntry(path="prod/config.env", version=2),
    ],
    unreadable_paths=[],
)
V1_MANIFEST = VaultManifest(
    root_path="",
    recursive=False,
    entries=[VaultManifestEntry(path="dev/config.env", version=None)],
    unreadable_paths=[],
)
RETURNED_API_SECRETS = [
    ("dev/config.env/DATABASE_PASSWORD", "postgres_password"),
    ("dev/config.env/SECRET_KEY", "my_secret_key"),
]


def _prepare_mocks(
    vault_api_client_cls_mock,
    collect_mock,
    prepare_mock,
    mount=VaultKvMount(name="secret", version="2"),
    manifest=V2_MANIFEST,
    scan_result=None,
    build_side_effect=None,
):
    vault_api_client_mock = Mock()
    vault_api_client_cls_mock.return_value = vault_api_client_mock
    vault_api_client_mock.get_kv_mounts.return_value = [mount]
    if build_side_effect is not None:
        vault_api_client_mock.build_manifest.side_effect = build_side_effect
    else:
        vault_api_client_mock.build_manifest.return_value = manifest
    vault_api_client_mock.scan_manifest.return_value = (
        scan_result
        if scan_result is not None
        else VaultScanResult(
            secrets=RETURNED_API_SECRETS,
            checked_paths=[entry.path for entry in manifest.entries],
        )
    )

    collect_mock.return_value = [
        SecretWithKey(key=key, value=value) for key, value in RETURNED_API_SECRETS
    ]
    prepare_mock.return_value = PreparedSecrets(
        payload=set([key for key, _ in RETURNED_API_SECRETS]),
        mapping={key: f"hash_{value}" for key, value in RETURNED_API_SECRETS},
    )
    return vault_api_client_mock


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
@pytest.mark.parametrize("recursive", [True, False])
def test_check_hashicorp_vault_cmd_lists_manifest_and_succeeds(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
    recursive,
):
    """
    GIVEN the hmsl check-secret-manager hashicorp-vault command
    WHEN every manifest entry is checked against a stable version
    THEN the paths and versions are listed before fetching, the secrets are
    checked and the command succeeds
    """
    args = [
        "hmsl",
        "check-secret-manager",
        "hashicorp-vault",
        "--url",
        "http://127.0.0.1:6789",
        "secret",
    ]
    if recursive:
        args.append("--recursive")

    vault_api_client_mock = _prepare_mocks(
        vault_api_client_cls_mock, collect_mock, prepare_mock
    )

    cmd_ret = cli_fs_runner.invoke(cli, args)

    vault_api_client_mock.build_manifest.assert_called_once_with(
        VaultKvMount(name="secret", version="2"), "", recursive
    )
    vault_api_client_mock.scan_manifest.assert_called_once_with(
        VaultKvMount(name="secret", version="2"), V2_MANIFEST
    )
    collect_mock.assert_called_once_with(RETURNED_API_SECRETS)
    prepare_mock.assert_called_once_with(
        collect_mock.return_value, NAMING_STRATEGIES["key"], full_hashes=True
    )
    check_secrets_mock.assert_called_once()

    assert cmd_ret.exit_code == ExitCode.SUCCESS
    assert "Building the list of paths to check...\n" in cmd_ret.output
    assert "2 paths will be checked:\n" in cmd_ret.output
    assert "- dev/config.env (version 1)\n" in cmd_ret.output
    assert "- prod/config.env (version 2)\n" in cmd_ret.output
    assert "Fetching secrets from Vault...\n" in cmd_ret.output
    assert "Checked 2 paths and got 2 secrets.\n" in cmd_ret.output


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
def test_check_hashicorp_vault_cmd_v1_manifest_without_versions(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
):
    """
    GIVEN a KV v1 mount
    WHEN listing the manifest
    THEN the paths are listed without a version
    """
    _prepare_mocks(
        vault_api_client_cls_mock,
        collect_mock,
        prepare_mock,
        mount=VaultKvMount(name="secret_v1", version="1"),
        manifest=V1_MANIFEST,
        scan_result=VaultScanResult(
            secrets=RETURNED_API_SECRETS, checked_paths=["dev/config.env"]
        ),
    )

    cmd_ret = cli_fs_runner.invoke(
        cli,
        [
            "hmsl",
            "check-secret-manager",
            "hashicorp-vault",
            "--url",
            "http://127.0.0.1:6789",
            "secret_v1",
        ],
    )

    assert cmd_ret.exit_code == ExitCode.SUCCESS
    assert "1 path will be checked:\n" in cmd_ret.output
    assert "- dev/config.env\n" in cmd_ret.output
    assert "(version" not in cmd_ret.output


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
def test_check_hashicorp_vault_cmd_incomplete_manifest_fails(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
):
    """
    GIVEN a scan where a path changed and another could not be read
    WHEN running the command
    THEN the two buckets are reported separately, the checked secrets are
    still checked and the command exits with the SCAN_FOUND_PROBLEMS code
    """
    scan_result = VaultScanResult(
        secrets=RETURNED_API_SECRETS,
        checked_paths=["dev/config.env"],
        changed_paths=["changed/config.env"],
        not_fetched_paths=["restricted/config.env"],
    )
    _prepare_mocks(
        vault_api_client_cls_mock,
        collect_mock,
        prepare_mock,
        scan_result=scan_result,
    )

    cmd_ret = cli_fs_runner.invoke(
        cli,
        [
            "hmsl",
            "check-secret-manager",
            "hashicorp-vault",
            "--url",
            "http://127.0.0.1:6789",
            "secret",
        ],
    )

    # The checked secrets are still sent for checking
    check_secrets_mock.assert_called_once()
    assert cmd_ret.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert "Checked 1 path and got 2 secrets.\n" in cmd_ret.output
    assert (
        "1 path changed during the scan and could not be checked. "
        "Re-run the command to check them:\n" in cmd_ret.output
    )
    assert "Error: - changed/config.env\n" in cmd_ret.output
    assert (
        "Could not fetch 1 path. Make sure your token has access to all the "
        "secrets in your vault:\n" in cmd_ret.output
    )
    assert "Error: - restricted/config.env\n" in cmd_ret.output
    assert "All right!" not in cmd_ret.output


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
def test_check_hashicorp_vault_cmd_incomplete_without_secrets_fails(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
):
    """
    GIVEN an incomplete scan with no secret to check
    WHEN running the command
    THEN no leaked-secret heading is shown, the API is not queried and the
    command still fails
    """
    scan_result = VaultScanResult(
        secrets=[],
        checked_paths=[],
        changed_paths=["changed/config.env"],
        not_fetched_paths=["restricted/config.env"],
    )
    _prepare_mocks(
        vault_api_client_cls_mock,
        collect_mock,
        prepare_mock,
        scan_result=scan_result,
    )
    prepare_mock.return_value = PreparedSecrets(payload=set(), mapping={})

    cmd_ret = cli_fs_runner.invoke(
        cli,
        [
            "hmsl",
            "check-secret-manager",
            "hashicorp-vault",
            "--url",
            "http://127.0.0.1:6789",
            "secret",
        ],
    )

    check_secrets_mock.assert_not_called()
    assert cmd_ret.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert "All right!" not in cmd_ret.output


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
def test_check_hashicorp_vault_cmd_empty_manifest_succeeds(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
):
    """
    GIVEN a complete but empty manifest
    WHEN running the command
    THEN the command reports there is nothing to check and succeeds
    """
    empty_manifest = VaultManifest(
        root_path="", recursive=False, entries=[], unreadable_paths=[]
    )
    _prepare_mocks(
        vault_api_client_cls_mock,
        collect_mock,
        prepare_mock,
        manifest=empty_manifest,
        scan_result=VaultScanResult(),
    )
    prepare_mock.return_value = PreparedSecrets(payload=set(), mapping={})

    cmd_ret = cli_fs_runner.invoke(
        cli,
        [
            "hmsl",
            "check-secret-manager",
            "hashicorp-vault",
            "--url",
            "http://127.0.0.1:6789",
            "secret",
        ],
    )

    check_secrets_mock.assert_not_called()
    assert cmd_ret.exit_code == ExitCode.SUCCESS
    assert "No secret path found to check.\n" in cmd_ret.output
    assert "All right! No leaked secret has been found.\n" in cmd_ret.output


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
def test_check_hashicorp_vault_cmd_forbidden_root_path(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
):
    """
    GIVEN a vault path that cannot be accessed at all
    WHEN building the manifest raises a forbidden error
    THEN an unexpected error is raised and the command fails with code 128
    """
    vault_api_client_mock = Mock()
    vault_api_client_cls_mock.return_value = vault_api_client_mock
    vault_api_client_mock.get_kv_mounts.return_value = [
        VaultKvMount(name="secret", version="2")
    ]
    vault_api_client_mock.build_manifest.side_effect = VaultForbiddenItemError()

    cmd_ret = cli_fs_runner.invoke(
        cli,
        [
            "hmsl",
            "check-secret-manager",
            "hashicorp-vault",
            "--url",
            "http://127.0.0.1:6789",
            "secret",
        ],
    )

    vault_api_client_mock.scan_manifest.assert_not_called()
    check_secrets_mock.assert_not_called()
    assert cmd_ret.exit_code == 128
    assert "access to the given path 'secret' was forbidden" in cmd_ret.output


@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
def test_check_hashicorp_vault_cmd_mount_not_found(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    cli_fs_runner,
):
    """
    GIVEN a mount name that does not exist
    WHEN running the command
    THEN an error is displayed and the command fails with code 128
    """
    vault_api_client_mock = Mock()
    vault_api_client_cls_mock.return_value = vault_api_client_mock
    vault_api_client_mock.get_kv_mounts.return_value = []

    cmd_ret = cli_fs_runner.invoke(
        cli,
        [
            "hmsl",
            "check-secret-manager",
            "hashicorp-vault",
            "--url",
            "http://127.0.0.1:6789",
            "secret",
        ],
    )

    assert cmd_ret.exit_code == 128
    assert (
        "Error: mount secret not found. Make sure it exists and that your "
        "token has access to it.\n" == cmd_ret.output
    )
