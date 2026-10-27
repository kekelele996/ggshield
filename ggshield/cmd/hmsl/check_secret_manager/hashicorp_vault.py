import os
from typing import Any, Optional, Tuple

import click

from ggshield.cmd.hmsl.hmsl_common_options import (
    full_hashes_option,
    naming_strategy_option,
)
from ggshield.cmd.hmsl.hmsl_utils import check_secrets
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.core import ui
from ggshield.core.errors import ExitCode, UnexpectedError
from ggshield.core.text_utils import pluralize
from ggshield.verticals.hmsl.collection import NamingStrategy, collect_list, prepare
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client import (
    VaultAPIClient,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.cli import (
    get_vault_cli_token,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultCliTokenFetchingError,
    VaultForbiddenItemError,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultManifest,
    VaultScanResult,
)


def _get_vault_token(use_vault_cli_token: bool) -> str:
    """
    Get the Vault token to use.
    """
    if use_vault_cli_token:
        try:
            return get_vault_cli_token()
        except VaultCliTokenFetchingError as exc:
            raise click.UsageError(
                f"could not get the token from Vault CLI: {str(exc)}"
            ) from exc

    env_token = os.getenv("VAULT_TOKEN")
    if env_token is None:
        raise click.UsageError(
            "you need to specify the Vault token to use, either through the VAULT_TOKEN"
            " environment variable or by using --use-cli-token to use the token "
            "from the Vault CLI."
        )

    return env_token


def _split_vault_mount_and_path(initial_path: str) -> Tuple[str, str]:
    """
    From a given initial path like secret/my_app/prod/env, split it in two:
    first the mount name, then the path.
    """
    split_path = initial_path.lstrip("/").split("/")
    return (split_path[0], "/".join(split_path[1:]).strip("/"))


def _display_manifest(mount: VaultKvMount, manifest: VaultManifest) -> None:
    """
    Display the paths and versions that will be checked during this scan,
    before any content is fetched.
    """
    entries = manifest.entries
    if not entries:
        ui.display_info("No secret path found to check.")
        return

    ui.display_info(
        f"{len(entries)} {pluralize('path', len(entries))} will be checked:"
    )
    for entry in entries:
        if mount.version == "2":
            version_info = (
                f"version {entry.version}"
                if entry.version is not None
                else "version unknown"
            )
            ui.display_info(f"- {entry.path} ({version_info})")
        else:
            # KV v1 mounts do not support versioning
            ui.display_info(f"- {entry.path}")


def _display_scan_result(result: VaultScanResult) -> None:
    """
    Display the result of the scan, separating the entries that were checked
    from the ones that changed during the scan and the ones that could not
    be read.
    """
    ui.display_info(
        f"Checked {len(result.checked_paths)} "
        f"{pluralize('path', len(result.checked_paths))} and got "
        f"{len(result.secrets)} {pluralize('secret', len(result.secrets))}."
    )

    if result.changed_paths:
        change_count = len(result.changed_paths)
        ui.display_error(
            f"{change_count} {pluralize('path', change_count)} changed during "
            "the scan and could not be checked. Re-run the command to check them:"
        )
        for path in result.changed_paths:
            ui.display_error(f"- {path}")

    if result.not_fetched_paths:
        not_fetched_count = len(result.not_fetched_paths)
        ui.display_error(
            f"Could not fetch {not_fetched_count} "
            f"{pluralize('path', not_fetched_count)}. Make sure your token has "
            "access to all the secrets in your vault:"
        )
        for path in result.not_fetched_paths:
            ui.display_error(f"- {path}")


@click.command()
@click.option(
    "--use-cli-token",
    "use_cli_token",
    is_flag=True,
    show_default=True,
    default=False,
    help="Instead of getting the token from the environment variable, "
    "get it from the CLI tool.",
)
@click.option(
    "--url",
    "url",
    required=False,
    type=str,
    help="The URL of the secret manager server.",
)
@click.option(
    "--recursive",
    "-r",
    "recursive",
    is_flag=True,
    show_default=True,
    default=False,
    help="If the secret manager path is a directory and not a file, explore recursively.",
)
@click.argument(
    "vault_path",
    type=str,
)
@add_common_options()
@text_json_format_option
@json_option
@full_hashes_option
@naming_strategy_option
@click.pass_context
def check_hashicorp_vault_cmd(
    ctx: click.Context,
    use_cli_token: bool,
    url: Optional[str],
    recursive: bool,
    vault_path: str,
    full_hashes: bool,
    naming_strategy: NamingStrategy,
    **kwargs: Any,
) -> int:
    """
    Check secrets of an Hashicorp Vault instance.
    Only compatible with the kv secret engines (v1 or v2) for now.

    The paths and their versions are listed before any content is fetched
    and the content is then read against this exact list. Paths that are
    added, deleted or modified while the scan is running, as well as paths
    the token cannot read, are reported separately: the command only
    succeeds if the whole list was checked against a stable version.

    Will use the VAULT_URL environment variable to get the Vault instance URL or
    the --url option if no environment variable is set.

    Will use the VAULT_TOKEN environment variable to authenticate, except
    if the --use-cli-token option is set.
    """

    # Get the Vault URL
    if url is None:
        url = os.getenv("VAULT_URL")
        if url is None:
            raise click.UsageError(
                "you need to specify the URL of your Vault, "
                "either through --url or in the VAULT_URL environment variable"
            )

    vault_token = _get_vault_token(use_cli_token)  # noqa: F841
    vault_client = VaultAPIClient(url, vault_token)

    # Get mount object and check it exists and we have access to it
    mount_name, secret_path = _split_vault_mount_and_path(vault_path)
    all_kv_mounts = list(vault_client.get_kv_mounts())
    mount = next((item for item in all_kv_mounts if item.name == mount_name), None)
    if mount is None:
        raise UnexpectedError(
            f"mount {mount_name} not found. Make sure it exists and "
            "that your token has access to it."
        )

    # Phase 1: build the manifest (paths and versions) without fetching content.
    ui.display_info("Building the list of paths to check...")
    try:
        manifest = vault_client.build_manifest(mount, secret_path, recursive)
    # catch this error here if the path provided is a file that we don't have access to
    except VaultForbiddenItemError:
        raise UnexpectedError(
            f"access to the given path '{vault_path}' was forbidden. "
            "Are you sure the permissions of the token are correct?"
        )

    _display_manifest(mount, manifest)

    # Phase 2: fetch the content against the manifest and reconcile it.
    ui.display_info("Fetching secrets from Vault...")
    try:
        result = vault_client.scan_manifest(mount, manifest)
    except VaultForbiddenItemError:
        raise UnexpectedError(
            f"access to the given path '{vault_path}' was forbidden. "
            "Are you sure the permissions of the token are correct?"
        )

    _display_scan_result(result)

    collected_secrets = collect_list(result.secrets)
    # full_hashes is True because we need the hashes to decrypt the secrets.
    # They will correctly be truncated by our client later (same as normal check cmd)
    prepared_secrets = prepare(collected_secrets, naming_strategy, full_hashes=True)

    # The scan is only successful when the manifest was fully reconciled.
    exit_code = ExitCode.SUCCESS if result.is_complete else ExitCode.SCAN_FOUND_PROBLEMS

    # Short-circuit if no secrets to check
    if len(prepared_secrets.payload) == 0:
        if result.is_complete:
            ui.display_heading("All right! No leaked secret has been found.")
        return exit_code

    check_secrets(
        ctx=ctx,
        prepared_secrets=prepared_secrets,
        full_hashes=full_hashes,
    )

    return exit_code
