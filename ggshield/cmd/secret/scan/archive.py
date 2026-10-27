import tempfile
from pathlib import Path
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.secret.scan.ui_utils import print_file_list
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.scan.file import create_files_from_paths
from ggshield.core.scanner_ui import create_scanner_ui
from ggshield.utils.archive import (
    ArchiveLimitsExceeded,
    UnsafeArchive,
    safe_unpack,
)
from ggshield.utils.click import RealPath
from ggshield.utils.files import ListFilesMode
from ggshield.verticals.secret import SecretScanCollection, SecretScanner
from ggshield.verticals.secret.secret_scan_collection import make_file_error


@click.command()
@click.argument(
    "path", nargs=1, type=RealPath(exists=True, resolve_path=True), required=True
)
@add_secret_scan_common_options()
@click.pass_context
def archive_cmd(
    ctx: click.Context,
    path: Path,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan an archive file. Supported archive formats are zip, whl, jar, tar, tar.gz, tar.bz2 and tar.xz.
    """
    # The temporary directory is removed whether the scan succeeds or fails (or
    # is refused because the archive is too big), so unpacked content never
    # lingers on the temporary disk.
    with tempfile.TemporaryDirectory(suffix="ggshield") as temp_dir:
        temp_path = Path(temp_dir)
        ui.display_heading("Unpacking archive")
        try:
            unpack_report = safe_unpack(path, extract_dir=temp_path)
        except ArchiveLimitsExceeded as exn:
            raise UnexpectedError(f'Refused to unpack "{path}" archive:\n{exn}')
        except UnsafeArchive as exn:
            raise UnexpectedError(f'Failed to unpack "{path}" archive: {exn}')
        except Exception as exn:
            raise UnexpectedError(f'Failed to unpack "{path}" archive: {exn}')

        ctx_obj = ContextObj.get(ctx)
        ctx_obj.client = create_client_from_config(ctx_obj.config)
        config = ctx_obj.config
        files, binary_paths = create_files_from_paths(
            paths=[temp_path],
            exclusion_regexes=ctx_obj.exclusion_regexes,
            list_files_mode=ListFilesMode.ALL,
        )
        print_file_list(files, binary_paths)
        ui.display_heading("Starting scan")

        with create_scanner_ui(len(files)) as scanner_ui:
            scan_context = ScanContext(
                scan_mode=ScanMode.ARCHIVE,
                command_path=ctx.command_path,
            )

            scanner = SecretScanner(
                client=ctx_obj.client,
                cache=ctx_obj.cache,
                scan_context=scan_context,
                secret_config=config.user_config.secret,
            )
            results = scanner.scan(files, scanner_ui=scanner_ui)

        # Members whose data could not be read are skipped during unpacking,
        # but they must make the scan report as incomplete: a clean result on
        # the remaining files does not mean the archive contained no secret.
        for member_name, reason in unpack_report.unread_members:
            results.errors.append(
                make_file_error(
                    member_name,
                    f"could not be extracted from the archive: {reason}",
                )
            )
            results.incomplete = True

        scan = SecretScanCollection(id=path, type="archive_scan", results=results)

        output_handler = create_output_handler(ctx)
        return output_handler.process_scan(scan)
