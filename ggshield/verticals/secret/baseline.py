"""
Baseline comparison for secret scans.

A baseline is a ggshield JSON scan report saved by a previous run
(`--json --output report.json` or `--save-baseline report.json`). Comparing a
new scan against it lets a team focus on secrets that are genuinely new:

- a secret already present in the baseline is still considered an *old*
  finding even if it moved to another file or to different line numbers,
  because findings are matched by their content hash (`ignore_sha`);
- a secret whose content changed at the same place (same file, same detector,
  nearby line) is reported as *modified*;
- secrets only in the new scan are *new*;
- secrets only in the baseline have been *removed*.

Only new and modified findings should gate a merge; the full scan report can
still be archived as-is.
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ggshield.core.errors import UnexpectedError
from ggshield.verticals.secret.secret_scan_collection import (
    Result,
    SecretScanCollection,
    group_secrets_by_ignore_sha,
)


# Maximum distance between line numbers, for two occurrences in the same file
# with the same detector (one disappearing from the baseline, one appearing in
# the current scan) to be considered the same secret whose content changed
# rather than a removal plus a new secret.
MODIFIED_LINE_WINDOW = 5


class BaselineStatus(str, Enum):
    NEW = "new"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"
    REMOVED = "removed"


@dataclass(frozen=True)
class FindingLocation:
    """Where a secret occurrence was found."""

    path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None

    def format(self) -> str:
        if self.line_start is None:
            return self.path
        if self.line_end is not None and self.line_end != self.line_start:
            return f"{self.path}:{self.line_start}-{self.line_end}"
        return f"{self.path}:{self.line_start}"


@dataclass
class BaselineIncident:
    ignore_sha: str
    detector: str
    locations: List[FindingLocation] = field(default_factory=list)


@dataclass
class IncidentChange:
    ignore_sha: str
    detector: str
    status: BaselineStatus
    locations: List[FindingLocation] = field(default_factory=list)
    # Where the finding was located in the baseline (unchanged/modified)
    previous_locations: List[FindingLocation] = field(default_factory=list)
    # Content hashes of the baseline findings this one replaces (modified)
    previous_shas: List[str] = field(default_factory=list)

    @property
    def relocated(self) -> bool:
        """True for an unchanged secret which moved to another file or line."""
        return self.status == BaselineStatus.UNCHANGED and sorted(
            self.locations, key=_location_sort_key
        ) != sorted(self.previous_locations, key=_location_sort_key)


@dataclass
class BaselineDiff:
    new: List[IncidentChange] = field(default_factory=list)
    modified: List[IncidentChange] = field(default_factory=list)
    unchanged: List[IncidentChange] = field(default_factory=list)
    removed: List[IncidentChange] = field(default_factory=list)

    @property
    def has_new_incidents(self) -> bool:
        """True if at least one finding is new or has new (modified) content."""
        return bool(self.new) or bool(self.modified)

    @property
    def change_by_sha(self) -> Dict[str, IncidentChange]:
        return {
            change.ignore_sha: change
            for change in self.new + self.modified + self.unchanged
        }

    @property
    def status_by_sha(self) -> Dict[str, BaselineStatus]:
        return {sha: change.status for sha, change in self.change_by_sha.items()}


def _location_sort_key(location: FindingLocation) -> Tuple[str, Optional[int]]:
    return location.path, location.line_start


class Baseline:
    """All incidents known from a previous scan, keyed by their content hash."""

    def __init__(
        self,
        incidents: Dict[str, BaselineIncident],
        source_path: Optional[Path] = None,
    ) -> None:
        self.incidents = incidents
        self.source_path = source_path

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        """Load a baseline from a ggshield JSON scan report."""
        try:
            text = path.read_text()
        except OSError as exc:
            raise UnexpectedError(f"Could not read baseline file {path}: {exc}")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise UnexpectedError(
                f"Could not parse baseline file {path}: {exc}.\n"
                "It must be a JSON report produced by ggshield "
                "(`ggshield secret scan --json` or `--save-baseline`)."
            )
        return cls.from_report_dict(data, source_path=path)

    @classmethod
    def from_report_dict(
        cls, report: Any, source_path: Optional[Path] = None
    ) -> "Baseline":
        """Build a baseline from a parsed ggshield JSON scan report."""
        if not isinstance(report, dict) or (
            "id" not in report and "total_incidents" not in report
        ):
            raise UnexpectedError(
                "The baseline file does not look like a ggshield JSON scan "
                "report: expected an object with scan results. Save one with "
                "`ggshield secret scan --json --output report.json` or with "
                "`--save-baseline report.json`."
            )
        incidents: Dict[str, BaselineIncident] = {}
        _collect_from_report_node(report, incidents)
        return cls(incidents, source_path=source_path)

    @classmethod
    def from_scan(cls, scan: SecretScanCollection) -> "Baseline":
        """Build a baseline from a live scan collection.

        Must be called before the scan results are censored, since
        `ignore_sha` is computed from the secret contents.
        """
        incidents: Dict[str, BaselineIncident] = {}
        for result in scan.get_all_results():
            _collect_from_result(result, incidents)
        return cls(incidents)


def _collect_from_result(
    result: Result, incidents: Dict[str, BaselineIncident]
) -> None:
    path = str(result.path)
    for sha, secrets in group_secrets_by_ignore_sha(result.secrets).items():
        entry = incidents.setdefault(
            sha, BaselineIncident(sha, secrets[0].detector_display_name)
        )
        for secret in secrets:
            for match in secret.matches:
                entry.locations.append(
                    FindingLocation(path, match.line_start, match.line_end)
                )


def _collect_from_report_node(
    node: Dict[str, Any], incidents: Dict[str, BaselineIncident]
) -> None:
    # The on-disk key is "entities_with_incidents"; accept "results" too for
    # reports produced or manipulated in Python.
    results = node.get("entities_with_incidents") or node.get("results") or []
    for result_dict in results:
        path = str(result_dict.get("filename", ""))
        for incident_dict in result_dict.get("incidents", []):
            sha = incident_dict.get("ignore_sha")
            if not sha:
                continue
            detector = incident_dict.get("type") or incident_dict.get("detector") or ""
            entry = incidents.setdefault(sha, BaselineIncident(sha, detector))
            for occurrence in incident_dict.get("occurrences", []):
                entry.locations.append(
                    FindingLocation(
                        path,
                        occurrence.get("line_start"),
                        occurrence.get("line_end"),
                    )
                )
    for sub_scan in node.get("scans") or []:
        _collect_from_report_node(sub_scan, incidents)


def _incident_changes(
    shas: Iterable[str],
    source_incidents: Dict[str, BaselineIncident],
    status: BaselineStatus,
    previous_incidents: Optional[Dict[str, BaselineIncident]] = None,
) -> List[IncidentChange]:
    changes = []
    for sha in sorted(shas):
        incident = source_incidents[sha]
        change = IncidentChange(
            ignore_sha=sha,
            detector=incident.detector,
            status=status,
            locations=list(incident.locations),
        )
        if previous_incidents is not None and sha in previous_incidents:
            change.previous_locations = list(previous_incidents[sha].locations)
        changes.append(change)
    return changes


def diff_scans(
    current: Baseline,
    baseline: Baseline,
    line_window: int = MODIFIED_LINE_WINDOW,
) -> BaselineDiff:
    """Compare a scan with a baseline.

    Findings are matched by `ignore_sha` (their content hash), so file and
    line changes do not matter for unchanged findings. A finding only in the
    current scan is paired with one only in the baseline as *modified* when
    they are in the same file, detected by the same detector and close in
    terms of line numbers; otherwise they are *new* and *removed*.
    """
    current_shas = set(current.incidents)
    baseline_shas = set(baseline.incidents)

    unchanged = _incident_changes(
        current_shas & baseline_shas,
        current.incidents,
        BaselineStatus.UNCHANGED,
        previous_incidents=baseline.incidents,
    )

    new_shas = current_shas - baseline_shas
    gone_shas = baseline_shas - current_shas

    modified_pairs = _pair_modified_occurrences(
        current, baseline, new_shas, gone_shas, line_window
    )

    # (current sha) -> list of matched baseline (sha, location)
    modified_current: Dict[str, List[Tuple[str, FindingLocation]]] = {}
    paired_baseline_shas: set[str] = set()
    for (
        current_sha,
        current_location,
        baseline_sha,
        baseline_location,
    ) in modified_pairs:
        modified_current.setdefault(current_sha, []).append(
            (baseline_sha, baseline_location)
        )
        paired_baseline_shas.add(baseline_sha)

    new_changes = []
    modified_changes = []
    for change in _incident_changes(new_shas, current.incidents, BaselineStatus.NEW):
        pairs = modified_current.get(change.ignore_sha)
        if not pairs:
            new_changes.append(change)
            continue
        change.status = BaselineStatus.MODIFIED
        # Keep previous locations and shas in a stable order
        ordered = sorted(pairs, key=lambda pair: _location_sort_key(pair[1]))
        change.previous_locations = [location for _, location in ordered]
        change.previous_shas = list(dict.fromkeys(sha for sha, _ in ordered))
        modified_changes.append(change)

    removed = _incident_changes(
        gone_shas - paired_baseline_shas,
        baseline.incidents,
        BaselineStatus.REMOVED,
    )

    return BaselineDiff(
        new=sorted(new_changes, key=lambda change: change.ignore_sha),
        modified=sorted(modified_changes, key=lambda change: change.ignore_sha),
        unchanged=sorted(unchanged, key=lambda change: change.ignore_sha),
        removed=sorted(removed, key=lambda change: change.ignore_sha),
    )


def _pair_modified_occurrences(
    current: Baseline,
    baseline: Baseline,
    new_shas: set[str],
    gone_shas: set[str],
    line_window: int,
) -> List[Tuple[str, FindingLocation, str, FindingLocation]]:
    """Greedily pair new occurrences with gone baseline occurrences.

    Pairs are unique on both sides and chosen by smallest line distance, so
    that each occurrence replaces at most one other occurrence.
    """
    current_occurrences: List[Tuple[str, FindingLocation]] = [
        (sha, location)
        for sha in sorted(new_shas)
        for location in current.incidents[sha].locations
        if location.line_start is not None
    ]
    baseline_occurrences: List[Tuple[str, FindingLocation]] = [
        (sha, location)
        for sha in sorted(gone_shas)
        for location in baseline.incidents[sha].locations
        if location.line_start is not None
    ]

    candidates: List[Tuple[int, int, int]] = []
    for current_index, (current_sha, current_location) in enumerate(
        current_occurrences
    ):
        for baseline_index, (baseline_sha, baseline_location) in enumerate(
            baseline_occurrences
        ):
            if current_location.path != baseline_location.path:
                continue
            if (
                current.incidents[current_sha].detector
                != baseline.incidents[baseline_sha].detector
            ):
                continue
            assert current_location.line_start is not None
            assert baseline_location.line_start is not None
            distance = abs(current_location.line_start - baseline_location.line_start)
            if distance <= line_window:
                candidates.append((distance, current_index, baseline_index))

    candidates.sort()
    used_current: set[int] = set()
    used_baseline: set[int] = set()
    pairs: List[Tuple[str, FindingLocation, str, FindingLocation]] = []
    for _, current_index, baseline_index in candidates:
        if current_index in used_current or baseline_index in used_baseline:
            continue
        used_current.add(current_index)
        used_baseline.add(baseline_index)
        current_sha, current_location = current_occurrences[current_index]
        baseline_sha, baseline_location = baseline_occurrences[baseline_index]
        pairs.append((current_sha, current_location, baseline_sha, baseline_location))
    return pairs
