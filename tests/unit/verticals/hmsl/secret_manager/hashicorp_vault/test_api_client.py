from unittest.mock import patch

import pytest
import requests

from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.api_client import (
    VaultAPIClient,
    VaultEntryStatus,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultAPIError,
    VaultForbiddenItemError,
    VaultNotFoundItemError,
    VaultPathIsNotADirectoryError,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultManifest,
    VaultManifestEntry,
    VaultScanResult,
)
from tests.unit.conftest import my_vcr


V2_MOUNT = VaultKvMount(name="secret", version="2")
V1_MOUNT = VaultKvMount(name="secret_v1", version="1")


@pytest.fixture(scope="module")
def vault_api_client():
    """
    Get a Vault API client with all rights.
    """
    return VaultAPIClient(
        vault_url="http://localhost:8200",
        api_token="my_vault_token",  # as defined in scripts/hmsl/hashicorp_vault.py
    )


@pytest.fixture(scope="module")
def restricted_vault_api_client():
    """
    Get a Vault API client with restricted permissions
    """
    return VaultAPIClient(
        vault_url="http://localhost:8200",
        api_token="restricted_token",  # as defined in scripts/hmsl/hashicorp_vault.py
    )


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_get_kv_mounts_api_endpoint.yaml",
    ignore_localhost=False,
)
def test_get_kv_mounts_api_endpoint(vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_mounts
    THEN I get all the kv mounts of this instance
    """
    kv_mounts = list(vault_api_client.get_kv_mounts())

    assert kv_mounts == [
        VaultKvMount(name="secret", version="2"),
        VaultKvMount(name="secret_v1", version="1"),
    ]


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        ("", ["b2b", "b2c"]),
        ("b2b", ["web_app", "worker"]),
        ("b2b/worker", ["config.env"]),
        ("b2b/web_app", ["config.env", "prod"]),
        ("b2c", ["web_app", "worker"]),
        ("b2c/worker", ["config.env"]),
        ("b2c/web_app", ["config.env", "prod"]),
        ("/b2b", ["web_app", "worker"]),
        ("/b2b/worker", ["config.env"]),
        ("/b2b/web_app", ["config.env", "prod"]),
        ("/b2c", ["web_app", "worker"]),
        ("/b2c/worker", ["config.env"]),
        ("/b2c/web_app", ["config.env", "prod"]),
    ],
)
def test_list_kv_items_v1(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items on a v1 mount
    THEN I get all the items
    """
    kv_mount = VaultKvMount(name="secret_v1", version="1")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_list_kv_items_v1_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        kv_items = list(vault_api_client.list_kv_items(kv_mount, vault_path))

    assert kv_items == expected_results


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_list_kv_items_not_a_directory.yaml",
    ignore_localhost=False,
)
def test_list_kv_items_not_a_directory(vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items with a path that is actually a file
    THEN VaultPathIsNotADirectoryError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultPathIsNotADirectoryError):
        vault_api_client.list_kv_items(kv_mount, "b2c/worker/config.env")


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_list_kv_items_forbidden.yaml",
    ignore_localhost=False,
)
def test_list_kv_items_forbidden(restricted_vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items on a path you don't have access to
    THEN VaultForbiddenItemError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultForbiddenItemError):
        restricted_vault_api_client.list_kv_items(kv_mount, "")


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        ("", ["b2b", "b2c"]),
        ("b2b", ["web_app", "worker"]),
        ("b2b/worker", ["config.env"]),
        ("b2b/web_app", ["config.env", "prod"]),
        ("b2c", ["web_app", "worker"]),
        ("b2c/worker", ["config.env"]),
        ("b2c/web_app", ["config.env", "prod"]),
        ("/b2b", ["web_app", "worker"]),
        ("/b2b/worker", ["config.env"]),
        ("/b2b/web_app", ["config.env", "prod"]),
        ("/b2c", ["web_app", "worker"]),
        ("/b2c/worker", ["config.env"]),
        ("/b2c/web_app", ["config.env", "prod"]),
    ],
)
def test_list_kv_items_v2(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling list_kv_items on a v2 mount
    THEN I get all the items
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_list_kv_items_v2_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        kv_items = list(vault_api_client.list_kv_items(kv_mount, vault_path))

    assert kv_items == expected_results


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        (
            "b2b/web_app/prod/config.env",
            [("b2b/web_app/prod/config.env/PROD_STUFF", "test")],
        ),
        (
            "b2b/worker/config.env",
            [
                ("b2b/worker/config.env/ANOTHER_PASSWORD", "my_secret_key"),
                ("b2b/worker/config.env/SECRET", "super_secret"),
            ],
        ),
    ],
)
def test_get_kv_secrets_v1(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets on a v1 mount
    THEN I get all the expected secrets
    """
    kv_mount = VaultKvMount(name="secret_v1", version="1")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_v1_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        secrets = vault_api_client.get_kv_secrets(kv_mount, vault_path)

    assert secrets == expected_results


@pytest.mark.parametrize(
    "vault_path, expected_results",
    [
        (
            "b2b/web_app/prod/config.env",
            [("b2b/web_app/prod/config.env/PROD_STUFF", "test")],
        ),
        (
            "b2b/worker/config.env",
            [
                ("b2b/worker/config.env/ANOTHER_PASSWORD", "my_secret_key"),
                ("b2b/worker/config.env/SECRET", "super_secret"),
            ],
        ),
    ],
)
def test_get_kv_secrets_v2(vault_api_client, vault_path, expected_results):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets on a v2 mount
    THEN I get all the expected secrets
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with my_vcr.use_cassette(
        f"test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_v2_{vault_path.replace('/', '_')}.yaml",
        ignore_localhost=False,
    ):
        secrets = vault_api_client.get_kv_secrets(kv_mount, vault_path)

    assert secrets == expected_results


def test_get_kv_secrets_v2_pinned_version():
    """
    GIVEN a KV v2 mount and a version number
    WHEN calling get_kv_secrets with a version
    THEN the version is passed as a query parameter and the content is parsed
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "_make_request",
        return_value={
            "data": {
                "data": {"PASSWORD": "my_password"},
                "metadata": {"version": 3},
            }
        },
    ) as make_request_mock:
        secrets = api_client.get_kv_secrets(V2_MOUNT, "my_path", version=3)

    make_request_mock.assert_called_once_with(
        "secret/data/my_path", params={"version": 3}
    )
    assert secrets == [("my_path/PASSWORD", "my_password")]


def test_get_kv_secrets_v1_ignores_version():
    """
    GIVEN a KV v1 mount which does not support versioning
    WHEN calling get_kv_secrets with a version
    THEN no version parameter is sent to the API
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "_make_request",
        return_value={"data": {"PASSWORD": "my_password"}},
    ) as make_request_mock:
        secrets = api_client.get_kv_secrets(V1_MOUNT, "my_path", version=3)

    make_request_mock.assert_called_once_with("secret_v1/my_path", params=None)
    assert secrets == [("my_path/PASSWORD", "my_password")]


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_not_found.yaml",
    ignore_localhost=False,
)
def test_get_kv_secrets_not_found(vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets with a path that doesn't exist
    THEN VaultNotFoundItemError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultNotFoundItemError):
        vault_api_client.get_kv_secrets(
            kv_mount, "these_are_not_the_secrets_you_are_looking_for.env"
        )


@my_vcr.use_cassette(
    "test_hmsl_secret_manager_hashicorp_vault_get_kv_secrets_forbidden.yaml",
    ignore_localhost=False,
)
def test_get_kv_secrets_forbidden(restricted_vault_api_client):
    """
    GIVEN a Vault instance and an API client
    WHEN calling get_kv_secrets on a path you don't have access to
    THEN VaultForbiddenItemError is raised
    """
    kv_mount = VaultKvMount(name="secret", version="2")

    with pytest.raises(VaultForbiddenItemError):
        restricted_vault_api_client.get_kv_secrets(kv_mount, "b2c/web_app/config.env")


def test_get_current_kv_version_v2():
    """
    GIVEN a KV v2 mount
    WHEN calling get_current_kv_version on a file
    THEN the current version number is read from the metadata endpoint
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "_make_request",
        return_value={"data": {"current_version": 4}},
    ) as make_request_mock:
        version = api_client.get_current_kv_version(V2_MOUNT, "b2b/worker/config.env")

    make_request_mock.assert_called_once_with("secret/metadata/b2b/worker/config.env")
    assert version == 4


def test_get_current_kv_version_v1():
    """
    GIVEN a KV v1 mount
    WHEN calling get_current_kv_version
    THEN None is returned and no API call is made
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(api_client, "_make_request") as make_request_mock:
        version = api_client.get_current_kv_version(V1_MOUNT, "my_path")

    assert version is None
    make_request_mock.assert_not_called()


@pytest.mark.parametrize(
    "status_code, expected_exception",
    [(403, VaultForbiddenItemError), (404, VaultNotFoundItemError)],
)
def test_get_current_kv_version_errors(status_code, expected_exception):
    """
    GIVEN a KV v2 mount
    WHEN the metadata endpoint returns 403 or 404
    THEN the corresponding exception is raised
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    response = requests.Response()
    response.status_code = status_code

    with patch.object(
        api_client,
        "_make_request",
        side_effect=requests.HTTPError(response=response),
    ):
        with pytest.raises(expected_exception):
            api_client.get_current_kv_version(V2_MOUNT, "my_path")


#
# build_manifest tests
#


def test_build_manifest_on_file_v2():
    """
    GIVEN a KV v2 mount and a file path
    WHEN calling build_manifest
    THEN the manifest contains the file pinned to its current version
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "list_kv_items",
        side_effect=VaultPathIsNotADirectoryError,
    ):
        with patch.object(
            api_client, "get_current_kv_version", return_value=3
        ) as version_mock:
            manifest = api_client.build_manifest(V2_MOUNT, "dev/config.env", True)

    assert manifest.root_path == "dev/config.env"
    assert manifest.recursive is True
    assert manifest.entries == [VaultManifestEntry(path="dev/config.env", version=3)]
    assert manifest.unreadable_paths == []
    version_mock.assert_called_once_with(V2_MOUNT, "dev/config.env")


def test_build_manifest_on_file_v1():
    """
    GIVEN a KV v1 mount and a file path
    WHEN calling build_manifest
    THEN the manifest contains the file without a version and no metadata
    call is made
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "list_kv_items",
        side_effect=VaultPathIsNotADirectoryError,
    ):
        with patch.object(
            api_client, "get_current_kv_version", return_value=None
        ) as version_mock:
            manifest = api_client.build_manifest(V1_MOUNT, "dev/config.env", True)

    assert manifest.entries == [VaultManifestEntry(path="dev/config.env", version=None)]
    assert manifest.unreadable_paths == []
    version_mock.assert_called_once_with(V1_MOUNT, "dev/config.env")


def test_build_manifest_recursive_directory():
    """
    GIVEN a KV v2 mount and a directory tree
    WHEN calling build_manifest with recursive=True
    THEN every file in the tree is listed with its version, sorted by path
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    tree = {
        "": ["dev", "prod"],
        "dev": ["config.env"],
        "prod": ["config.env", "nested"],
        "prod/nested": ["config.env"],
    }

    def list_items(mount, path):
        if path in tree:
            return tree[path]
        raise VaultPathIsNotADirectoryError()

    def current_version(mount, path):
        return len(path)

    with patch.object(api_client, "list_kv_items", side_effect=list_items):
        with patch.object(
            api_client, "get_current_kv_version", side_effect=current_version
        ):
            manifest = api_client.build_manifest(V2_MOUNT, "", True)

    assert [(entry.path, entry.version) for entry in manifest.entries] == [
        ("dev/config.env", len("dev/config.env")),
        ("prod/config.env", len("prod/config.env")),
        ("prod/nested/config.env", len("prod/nested/config.env")),
    ]
    assert manifest.unreadable_paths == []


def test_build_manifest_non_recursive_directory():
    """
    GIVEN a directory containing files and subdirectories
    WHEN calling build_manifest with recursive=False
    THEN only the files at the first level are in the manifest
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    tree = {
        "": ["config.env", "dev"],
        "dev": ["config.env"],
    }

    def list_items(mount, path):
        if path in tree:
            return tree[path]
        raise VaultPathIsNotADirectoryError()

    with patch.object(api_client, "list_kv_items", side_effect=list_items):
        with patch.object(api_client, "get_current_kv_version", return_value=1):
            manifest = api_client.build_manifest(V2_MOUNT, "", False)

    assert [entry.path for entry in manifest.entries] == ["config.env"]
    assert manifest.unreadable_paths == []


def test_build_manifest_forbidden_subdirectory():
    """
    GIVEN a directory containing a subdirectory that cannot be listed
    WHEN calling build_manifest
    THEN the subdirectory is recorded in unreadable_paths
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    def list_items(mount, path):
        if path == "":
            return ["allowed", "restricted"]
        if path == "allowed":
            raise VaultPathIsNotADirectoryError()
        if path == "restricted":
            raise VaultForbiddenItemError()
        raise VaultPathIsNotADirectoryError()

    with patch.object(api_client, "list_kv_items", side_effect=list_items):
        with patch.object(api_client, "get_current_kv_version", return_value=1):
            manifest = api_client.build_manifest(V2_MOUNT, "", True)

    assert [entry.path for entry in manifest.entries] == ["allowed"]
    assert manifest.unreadable_paths == ["restricted"]


def test_build_manifest_forbidden_file_metadata():
    """
    GIVEN a file whose metadata cannot be read on a KV v2 mount
    WHEN calling build_manifest
    THEN the file is recorded in unreadable_paths
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "list_kv_items",
        side_effect=VaultPathIsNotADirectoryError,
    ):
        with patch.object(
            api_client,
            "get_current_kv_version",
            side_effect=VaultForbiddenItemError(),
        ):
            manifest = api_client.build_manifest(V2_MOUNT, "secret_path", True)

    assert manifest.entries == []
    assert manifest.unreadable_paths == ["secret_path"]


def test_build_manifest_file_deleted_during_enumeration():
    """
    GIVEN a file that disappears between the listing and the metadata read
    WHEN calling build_manifest on a KV v2 mount
    THEN the file is kept in the manifest without a version
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client,
        "list_kv_items",
        side_effect=VaultPathIsNotADirectoryError,
    ):
        with patch.object(
            api_client,
            "get_current_kv_version",
            side_effect=VaultNotFoundItemError(),
        ):
            manifest = api_client.build_manifest(V2_MOUNT, "secret_path", True)

    assert manifest.entries == [VaultManifestEntry("secret_path", None)]
    assert manifest.unreadable_paths == []


def test_build_manifest_root_forbidden():
    """
    GIVEN a root path that cannot be listed
    WHEN calling build_manifest
    THEN VaultForbiddenItemError is propagated
    """
    api_client = VaultAPIClient("vault_url", "vault_token")

    with patch.object(
        api_client, "list_kv_items", side_effect=VaultForbiddenItemError()
    ):
        with pytest.raises(VaultForbiddenItemError):
            api_client.build_manifest(V2_MOUNT, "", True)


#
# Entry fetching and verification tests
#


def test_fetch_v2_entry_stable():
    """
    GIVEN a KV v2 entry whose version is still current when verified
    WHEN fetching it
    THEN it is checked and the pinned version is used
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=1)

    with patch.object(
        api_client,
        "_get_kv_secrets_raw",
        return_value=({"PASSWORD": "secret"}, {"version": 1}),
    ) as raw_mock:
        with patch.object(
            api_client, "get_current_kv_version", return_value=1
        ) as current_mock:
            status, secrets = api_client._fetch_v2_entry(V2_MOUNT, entry)

    assert status == VaultEntryStatus.CHECKED
    assert secrets == [("dev/config.env/PASSWORD", "secret")]
    raw_mock.assert_called_once_with(V2_MOUNT, "dev/config.env", 1)
    current_mock.assert_called_once_with(V2_MOUNT, "dev/config.env")


def test_fetch_v2_entry_changed_then_reread():
    """
    GIVEN a KV v2 entry updated between the manifest read and the fetch
    WHEN the newest version is stable on the re-read
    THEN the entry is checked against the new version
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=1)

    raw_responses = [
        ({"PASSWORD": "old"}, {"version": 1}),
        ({"PASSWORD": "new"}, {"version": 2}),
    ]

    with patch.object(
        api_client, "_get_kv_secrets_raw", side_effect=raw_responses
    ) as raw_mock:
        with patch.object(api_client, "get_current_kv_version", side_effect=[2, 2]):
            status, secrets = api_client._fetch_v2_entry(V2_MOUNT, entry)

    assert status == VaultEntryStatus.CHECKED
    assert secrets == [("dev/config.env/PASSWORD", "new")]
    assert raw_mock.call_args_list[0].args == (V2_MOUNT, "dev/config.env", 1)
    assert raw_mock.call_args_list[1].args == (V2_MOUNT, "dev/config.env", 2)


def test_fetch_v2_entry_keeps_changing():
    """
    GIVEN a KV v2 entry that keeps being updated during the scan
    WHEN the re-read is not stable either
    THEN the entry is marked as changed and no secret is returned
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=1)

    raw_responses = [
        ({"PASSWORD": "old"}, {"version": 1}),
        ({"PASSWORD": "new"}, {"version": 2}),
    ]

    with patch.object(
        api_client, "_get_kv_secrets_raw", side_effect=raw_responses
    ) as raw_mock:
        with patch.object(api_client, "get_current_kv_version", side_effect=[2, 3]):
            status, secrets = api_client._fetch_v2_entry(V2_MOUNT, entry)

    assert status == VaultEntryStatus.CHANGED
    assert secrets == []
    assert raw_mock.call_count == 2


def test_fetch_v2_entry_deleted_when_fetching():
    """
    GIVEN a KV v2 entry deleted after the manifest was built
    WHEN the pinned version read returns 404
    THEN the entry is marked as changed
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=1)

    with patch.object(
        api_client,
        "_get_kv_secrets_raw",
        side_effect=VaultNotFoundItemError(),
    ):
        status, secrets = api_client._fetch_v2_entry(V2_MOUNT, entry)

    assert status == VaultEntryStatus.CHANGED
    assert secrets == []


def test_fetch_v2_entry_forbidden():
    """
    GIVEN a KV v2 entry that cannot be read
    WHEN the content read returns 403
    THEN the entry is marked as unreadable
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=1)

    with patch.object(
        api_client,
        "_get_kv_secrets_raw",
        side_effect=VaultForbiddenItemError(),
    ):
        status, secrets = api_client._fetch_v2_entry(V2_MOUNT, entry)

    assert status == VaultEntryStatus.UNREADABLE
    assert secrets == []


def test_fetch_v2_entry_forbidden_verification():
    """
    GIVEN a KV v2 entry whose content can be read but whose metadata cannot
    WHEN the version verification returns 403
    THEN the entry is marked as unreadable, since its version cannot be verified
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=1)

    with patch.object(
        api_client,
        "_get_kv_secrets_raw",
        return_value=({"PASSWORD": "secret"}, {"version": 1}),
    ):
        with patch.object(
            api_client,
            "get_current_kv_version",
            side_effect=VaultForbiddenItemError(),
        ):
            status, secrets = api_client._fetch_v2_entry(V2_MOUNT, entry)

    assert status == VaultEntryStatus.UNREADABLE
    assert secrets == []


def test_fetch_v1_entry_stable():
    """
    GIVEN a KV v1 entry
    WHEN two consecutive reads return the same content
    THEN the entry is checked
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=None)
    secrets = [("dev/config.env/PASSWORD", "secret")]

    with patch.object(
        api_client, "get_kv_secrets", side_effect=[secrets, secrets]
    ) as get_secrets_mock:
        status, returned_secrets = api_client._fetch_v1_entry(V1_MOUNT, entry)

    assert status == VaultEntryStatus.CHECKED
    assert returned_secrets == secrets
    assert get_secrets_mock.call_count == 2


def test_fetch_v1_entry_changed_then_reread():
    """
    GIVEN a KV v1 entry modified between the two first reads
    WHEN the re-read is identical to the previous one
    THEN the entry is checked against the new content
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=None)
    old_secrets = [("dev/config.env/PASSWORD", "old")]
    new_secrets = [("dev/config.env/PASSWORD", "new")]

    with patch.object(
        api_client,
        "get_kv_secrets",
        side_effect=[old_secrets, new_secrets, new_secrets],
    ) as get_secrets_mock:
        status, returned_secrets = api_client._fetch_v1_entry(V1_MOUNT, entry)

    assert status == VaultEntryStatus.CHECKED
    assert returned_secrets == new_secrets
    assert get_secrets_mock.call_count == 3


def test_fetch_v1_entry_keeps_changing():
    """
    GIVEN a KV v1 entry whose content keeps changing
    WHEN no two consecutive reads agree
    THEN the entry is marked as changed
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=None)

    with patch.object(
        api_client,
        "get_kv_secrets",
        side_effect=[
            [("dev/config.env/PASSWORD", "one")],
            [("dev/config.env/PASSWORD", "two")],
            [("dev/config.env/PASSWORD", "three")],
        ],
    ) as get_secrets_mock:
        status, secrets = api_client._fetch_v1_entry(V1_MOUNT, entry)

    assert status == VaultEntryStatus.CHANGED
    assert secrets == []
    assert get_secrets_mock.call_count == 3


@pytest.mark.parametrize(
    "exception, expected_status",
    [
        (VaultNotFoundItemError(), VaultEntryStatus.CHANGED),
        (VaultForbiddenItemError(), VaultEntryStatus.UNREADABLE),
    ],
)
def test_fetch_v1_entry_errors(exception, expected_status):
    """
    GIVEN a KV v1 entry
    WHEN the first read returns 404 or 403
    THEN the entry is respectively marked as changed or unreadable
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    entry = VaultManifestEntry("dev/config.env", version=None)

    with patch.object(api_client, "get_kv_secrets", side_effect=exception):
        status, secrets = api_client._fetch_v1_entry(V1_MOUNT, entry)

    assert status == expected_status
    assert secrets == []


#
# scan_manifest / get_secrets tests
#


def test_scan_manifest_all_checked():
    """
    GIVEN a manifest whose entries are all stable and whose scope does not
    change during the scan
    WHEN calling scan_manifest
    THEN every entry is checked and the result is complete
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[
            VaultManifestEntry("dev/config.env", version=1),
            VaultManifestEntry("prod/config.env", version=2),
        ],
        unreadable_paths=[],
    )

    def fetch_entry(mount, entry):
        return (
            VaultEntryStatus.CHECKED,
            [(f"{entry.path}/PASSWORD", "secret")],
        )

    with patch.object(api_client, "_fetch_entry", side_effect=fetch_entry):
        with patch.object(api_client, "build_manifest", return_value=manifest):
            result = api_client.scan_manifest(V2_MOUNT, manifest)

    assert result.checked_paths == ["dev/config.env", "prod/config.env"]
    assert result.changed_paths == []
    assert result.not_fetched_paths == []
    assert result.secrets == [
        ("dev/config.env/PASSWORD", "secret"),
        ("prod/config.env/PASSWORD", "secret"),
    ]
    assert result.is_complete is True


def test_scan_manifest_unreadable_seeded():
    """
    GIVEN a manifest built with a directory that could not be listed
    WHEN calling scan_manifest
    THEN the directory is in the unreadable bucket and the result is not
    complete
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=["restricted"],
    )

    with patch.object(
        api_client,
        "_fetch_entry",
        return_value=(
            VaultEntryStatus.CHECKED,
            [("dev/config.env/PASSWORD", "secret")],
        ),
    ):
        with patch.object(api_client, "build_manifest", return_value=manifest):
            result = api_client.scan_manifest(V2_MOUNT, manifest)

    assert result.checked_paths == ["dev/config.env"]
    assert result.not_fetched_paths == ["restricted"]
    assert result.changed_paths == []
    assert result.is_complete is False


def test_scan_manifest_deleted_during_scan():
    """
    GIVEN an entry checked during fetching but missing from the final
    enumeration
    WHEN calling scan_manifest
    THEN the entry and its secrets move to the changed bucket
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    initial_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[
            VaultManifestEntry("dev/config.env", version=1),
            VaultManifestEntry("gone/config.env", version=1),
        ],
        unreadable_paths=[],
    )
    final_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=[],
    )

    def fetch_entry(mount, entry):
        return (
            VaultEntryStatus.CHECKED,
            [(f"{entry.path}/PASSWORD", "secret")],
        )

    with patch.object(api_client, "_fetch_entry", side_effect=fetch_entry):
        with patch.object(
            api_client,
            "build_manifest",
            return_value=final_manifest,
        ):
            result = api_client.scan_manifest(V2_MOUNT, initial_manifest)

    assert result.checked_paths == ["dev/config.env"]
    assert result.changed_paths == ["gone/config.env"]
    assert result.not_fetched_paths == []
    assert result.secrets == [("dev/config.env/PASSWORD", "secret")]
    assert result.is_complete is False


def test_scan_manifest_added_during_scan():
    """
    GIVEN a new secret appearing while the scan is running
    WHEN calling scan_manifest
    THEN the new entry is fetched and verified like the others
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    initial_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=[],
    )
    final_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[
            VaultManifestEntry("dev/config.env", version=1),
            VaultManifestEntry("new/config.env", version=1),
        ],
        unreadable_paths=[],
    )

    def fetch_entry(mount, entry):
        return (
            VaultEntryStatus.CHECKED,
            [(f"{entry.path}/PASSWORD", "secret")],
        )

    with patch.object(
        api_client, "_fetch_entry", side_effect=fetch_entry
    ) as fetch_mock:
        with patch.object(
            api_client,
            "build_manifest",
            return_value=final_manifest,
        ):
            result = api_client.scan_manifest(V2_MOUNT, initial_manifest)

    assert result.checked_paths == ["dev/config.env", "new/config.env"]
    assert result.changed_paths == []
    assert result.is_complete is True
    assert fetch_mock.call_count == 2


def test_scan_manifest_added_but_changing():
    """
    GIVEN a new secret appearing and being modified while the scan runs
    WHEN calling scan_manifest
    THEN the new entry ends up in the changed bucket
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    initial_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=[],
    )
    final_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[
            VaultManifestEntry("dev/config.env", version=1),
            VaultManifestEntry("new/config.env", version=1),
        ],
        unreadable_paths=[],
    )

    def fetch_entry(mount, entry):
        if entry.path == "new/config.env":
            return VaultEntryStatus.CHANGED, []
        return (
            VaultEntryStatus.CHECKED,
            [("dev/config.env/PASSWORD", "secret")],
        )

    with patch.object(api_client, "_fetch_entry", side_effect=fetch_entry):
        with patch.object(
            api_client,
            "build_manifest",
            return_value=final_manifest,
        ):
            result = api_client.scan_manifest(V2_MOUNT, initial_manifest)

    assert result.checked_paths == ["dev/config.env"]
    assert result.changed_paths == ["new/config.env"]
    assert result.is_complete is False


def test_scan_manifest_directory_becomes_unreadable():
    """
    GIVEN a directory that becomes unreadable between the two enumerations
    WHEN calling scan_manifest
    THEN the directory is added to the unreadable bucket
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    initial_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=[],
    )
    final_manifest = VaultManifest(
        root_path="",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=["restricted"],
    )

    with patch.object(
        api_client,
        "_fetch_entry",
        return_value=(
            VaultEntryStatus.CHECKED,
            [("dev/config.env/PASSWORD", "secret")],
        ),
    ):
        with patch.object(
            api_client,
            "build_manifest",
            return_value=final_manifest,
        ):
            result = api_client.scan_manifest(V2_MOUNT, initial_manifest)

    assert result.checked_paths == ["dev/config.env"]
    assert result.not_fetched_paths == ["restricted"]
    assert result.is_complete is False


def test_get_secrets_builds_and_scans_manifest():
    """
    GIVEN a mount, a path and the recursive flag
    WHEN calling get_secrets
    THEN a manifest is built and immediately scanned with the same parameters
    """
    api_client = VaultAPIClient("vault_url", "vault_token")
    manifest = VaultManifest(
        root_path="dev",
        recursive=True,
        entries=[VaultManifestEntry("dev/config.env", version=1)],
        unreadable_paths=[],
    )
    expected_result = VaultScanResult(
        secrets=[("dev/config.env/PASSWORD", "secret")],
        checked_paths=["dev/config.env"],
    )

    with patch.object(
        api_client, "build_manifest", return_value=manifest
    ) as build_mock:
        with patch.object(
            api_client, "scan_manifest", return_value=expected_result
        ) as scan_mock:
            result = api_client.get_secrets(V2_MOUNT, "dev", True)

    build_mock.assert_called_once_with(V2_MOUNT, "dev", True)
    scan_mock.assert_called_once_with(V2_MOUNT, manifest)
    assert result == expected_result


def test_make_request_network_error(vault_api_client):
    """
    GIVEN a Vault API client
    WHEN a network error occurs during _make_request
    THEN a VaultAPIError is raised with a descriptive message
    """
    with patch.object(
        vault_api_client.session,
        "request",
        side_effect=requests.exceptions.ConnectionError("network down"),
    ):
        with pytest.raises(VaultAPIError, match="Network error contacting Vault"):
            vault_api_client._make_request("sys/mounts")
