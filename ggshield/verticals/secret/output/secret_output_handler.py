from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

import click
from pygitguardian import GGClient

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import ExitCode
from ggshield.verticals.secret import SecretScanCollection
from ggshield.verticals.secret.baseline import Baseline, BaselineDiff, diff_scans


class SecretOutputHandler(ABC):
    verbose: bool = False
    client: Optional[GGClient] = None
    output: Optional[Path] = None
    use_stderr: bool = False

    def __init__(
        self,
        verbose: bool,
        secret_config: SecretConfig,
        client: Optional[GGClient] = None,
        output: Optional[Path] = None,
        baseline: Optional[Baseline] = None,
        save_baseline: Optional[Path] = None,
    ):
        self.secret_config = secret_config
        self.show_secrets = secret_config.show_secrets
        self.verbose = verbose
        self.client = client
        self.output = output
        self.ignore_known_secrets = secret_config.ignore_known_secrets
        self.with_incident_details = secret_config.with_incident_details
        self.baseline = baseline
        self.save_baseline = save_baseline
        # Set by process_scan() when a baseline is compared against
        self.baseline_diff: Optional[BaselineDiff] = None

    def get_baseline_diff(self, scan: SecretScanCollection) -> Optional[BaselineDiff]:
        """Compare the scan with the baseline, computing the result lazily.

        Must run before results are censored/serialized, since ignore_sha is
        derived from the secret contents.
        """
        if self.baseline is None:
            return None
        if self.baseline_diff is None:
            self.baseline_diff = diff_scans(Baseline.from_scan(scan), self.baseline)
        return self.baseline_diff

    def process_scan(self, scan: SecretScanCollection) -> ExitCode:
        """Process a scan collection, write the report to :attr:`self.output`

        :param scan: The scan collection to process
        :return: The exit code
        """
        self.get_baseline_diff(scan)
        # The baseline archive is always a full JSON report, regardless of
        # the format used for the displayed output.
        if self.save_baseline is not None:
            self.save_baseline.write_text(self._build_baseline_report(scan))
        text = self._process_scan_impl(scan)
        if self.output:
            self.output.write_text(text)
        else:
            click.echo(text, err=self.use_stderr)
        return self._get_exit_code(scan)

    def _build_baseline_report(self, scan: SecretScanCollection) -> str:
        """Serialize the full scan as a ggshield JSON report, suitable for use
        as a future :attr:`self.baseline`."""
        # Imported here to avoid a circular import
        from ggshield.verticals.secret.output.secret_json_output_handler import (
            SecretJSONOutputHandler,
        )

        return SecretJSONOutputHandler(
            verbose=False,
            secret_config=self.secret_config,
            client=self.client,
        )._process_scan_impl(scan)

    @abstractmethod
    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        """Implementation of scan processing,
        called by :meth:`OutputHandler.process_scan`

        Must return a string for the report.

        :param scan: The scan collection to process
        :return: The content
        """
        raise NotImplementedError()

    def _get_exit_code(self, scan: SecretScanCollection) -> ExitCode:
        if self.baseline_diff is not None:
            # With a baseline only new or modified (new content) findings gate
            # the merge; unchanged and removed findings are informational.
            if self.baseline_diff.has_new_incidents:
                return ExitCode.SCAN_FOUND_PROBLEMS
            return ExitCode.SUCCESS
        if scan.total_secrets_count > 0:
            return ExitCode.SCAN_FOUND_PROBLEMS
        return ExitCode.SUCCESS
