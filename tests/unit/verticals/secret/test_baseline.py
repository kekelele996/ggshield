import json
import re
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

import pytest

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import UnexpectedError
from ggshield.core.scan import StringScannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import (
    Result,
    Results,
    SecretScanCollection,
)
from ggshield.verticals.secret.baseline import (
    Baseline,
    BaselineIncident,
    BaselineStatus,
    FindingLocation,
    diff_scans,
)
from ggshield.verticals.secret.output import (
    SecretJSONOutputHandler,
    SecretTextOutputHandler,
)
from ggshield.verticals.secret.secret_scan_collection import (
    group_secrets_by_ignore_sha,
)
from tests.unit.conftest import (
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    TWO_POLICY_BREAKS,
)


#
# Report dict helpers
#


def _incident_dict(
    sha: str,
    detector: str = "AWS Key",
    line_start: int = 10,
    line_end: Optional[int] = None,
) -> Dict[str, Any]:
    return {
        "ignore_sha": sha,
        "type": detector,
        "policy": "Secrets detection",
        "total_occurrences": 1,
        "occurrences": [
            {
                "match": "REDACTED",
                "match_type": "apikey",
                "line_start": line_start,
                "line_end": line_end if line_end is not None else line_start,
                "index_start": 0,
                "index_end": 8,
            }
        ],
    }


def _result_dict(filename: str, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "filename": filename,
        "mode": "FILE",
        "incidents": incidents,
        "total_incidents": len(incidents),
        "total_occurrences": sum(i["total_occurrences"] for i in incidents),
    }


def _report_dict(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_incidents = sum(result["total_incidents"] for result in results)
    total_occurrences = sum(result["total_occurrences"] for result in results)
    return {
        "id": "path",
        "type": "path_scan",
        "entities_with_incidents": results,
        "total_incidents": total_incidents,
        "total_occurrences": total_occurrences,
    }


def _baseline_from_specs(
    specs: List[Tuple[str, str, str, int]],
) -> Baseline:
    """specs: (sha, detector, path, line)"""
    return Baseline(
        {
            sha: BaselineIncident(
                sha,
                detector,
                [FindingLocation(path, line, line)],
            )
            for sha, detector, path, line in specs
        }
    )


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64


#
# Loading
#


def test_baseline_from_report_dict_flat():
    """
    GIVEN a ggshield JSON report
    WHEN building a baseline from it
    THEN incidents are indexed by ignore_sha with their locations
    """
    report = _report_dict(
        [
            _result_dict(
                "config/app.env",
                [_incident_dict(SHA_A, line_start=3)],
            )
        ]
    )
    baseline = Baseline.from_report_dict(report)
    assert set(baseline.incidents) == {SHA_A}
    incident = baseline.incidents[SHA_A]
    assert incident.detector == "AWS Key"
    assert incident.locations == [FindingLocation("config/app.env", 3, 3)]


def test_baseline_from_report_dict_nested_scans():
    """
    GIVEN a report with nested scans (commit-range style)
    WHEN building a baseline
    THEN incidents in nested scans are collected too
    """
    report = {
        "id": "repo",
        "type": "commit-range",
        "scans": [
            _report_dict([_result_dict("a.txt", [_incident_dict(SHA_A)])]),
            _report_dict([_result_dict("b.txt", [_incident_dict(SHA_B)])]),
        ],
        "total_incidents": 2,
        "total_occurrences": 2,
    }
    baseline = Baseline.from_report_dict(report)
    assert set(baseline.incidents) == {SHA_A, SHA_B}


def test_baseline_from_report_dict_accepts_results_key():
    """
    GIVEN a report using the "results" key instead of "entities_with_incidents"
    WHEN building a baseline
    THEN it is accepted
    """
    report = _report_dict([_result_dict("a.txt", [_incident_dict(SHA_A)])])
    report["results"] = report.pop("entities_with_incidents")
    baseline = Baseline.from_report_dict(report)
    assert SHA_A in baseline.incidents


@pytest.mark.parametrize(
    "data",
    [
        [],
        "not a dict",
        {"foo": "bar"},
        {"entities_with_incidents": []},
    ],
)
def test_baseline_from_report_dict_invalid(data):
    with pytest.raises(UnexpectedError):
        Baseline.from_report_dict(data)


def test_baseline_load_bad_json(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{not json")
    with pytest.raises(UnexpectedError, match="parse"):
        Baseline.load(path)


#
# Diff
#


def test_diff_identical_is_unchanged():
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])

    diff = diff_scans(current, baseline)

    assert diff.has_new_incidents is False
    assert [c.ignore_sha for c in diff.unchanged] == [SHA_A]
    assert diff.new == []
    assert diff.modified == []
    assert diff.removed == []
    assert diff.unchanged[0].relocated is False
    assert diff.status_by_sha[SHA_A] == BaselineStatus.UNCHANGED


def test_diff_same_sha_moved_line_is_unchanged():
    """The same secret at a different line number is still an old finding."""
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 42)])

    diff = diff_scans(current, baseline)

    assert diff.has_new_incidents is False
    (change,) = diff.unchanged
    assert change.relocated is True
    assert change.previous_locations == [FindingLocation("a.txt", 10, 10)]


def test_diff_same_sha_moved_file_is_unchanged():
    """The same secret moved to another file is still an old finding."""
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "old/a.txt", 10)])
    current = _baseline_from_specs([(SHA_A, "AWS Key", "new/b.txt", 10)])

    diff = diff_scans(current, baseline)

    assert diff.has_new_incidents is False
    (change,) = diff.unchanged
    assert change.relocated is True
    assert change.locations == [FindingLocation("new/b.txt", 10, 10)]


def test_diff_new_secret():
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs(
        [
            (SHA_A, "AWS Key", "a.txt", 10),
            (SHA_B, "GitHub Token", "b.txt", 2),
        ]
    )

    diff = diff_scans(current, baseline)

    assert diff.has_new_incidents is True
    assert [c.ignore_sha for c in diff.new] == [SHA_B]
    assert [c.ignore_sha for c in diff.unchanged] == [SHA_A]
    assert diff.removed == []


def test_diff_removed_secret():
    baseline = _baseline_from_specs(
        [
            (SHA_A, "AWS Key", "a.txt", 10),
            (SHA_B, "GitHub Token", "b.txt", 2),
        ]
    )
    current = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])

    diff = diff_scans(current, baseline)

    assert diff.has_new_incidents is False
    assert [c.ignore_sha for c in diff.removed] == [SHA_B]
    (change,) = diff.removed
    assert change.locations == [FindingLocation("b.txt", 2, 2)]


def test_diff_modified_same_line():
    """A different secret content at the same place is a modification."""
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_B, "AWS Key", "a.txt", 10)])

    diff = diff_scans(current, baseline)

    assert diff.has_new_incidents is True
    assert diff.new == []
    assert diff.removed == []
    (change,) = diff.modified
    assert change.ignore_sha == SHA_B
    assert change.previous_shas == [SHA_A]
    assert change.previous_locations == [FindingLocation("a.txt", 10, 10)]


@pytest.mark.parametrize("shift", [1, 5])
def test_diff_modified_within_line_window(shift):
    """Small line shifts (edited file) still identify a content change."""
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_B, "AWS Key", "a.txt", 10 + shift)])

    diff = diff_scans(current, baseline)

    assert [c.ignore_sha for c in diff.modified] == [SHA_B]
    assert diff.new == []
    assert diff.removed == []


def test_diff_far_line_is_new_and_removed():
    """Too far apart to be the same rotated secret: new + removed."""
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_B, "AWS Key", "a.txt", 100)])

    diff = diff_scans(current, baseline)

    assert [c.ignore_sha for c in diff.new] == [SHA_B]
    assert [c.ignore_sha for c in diff.removed] == [SHA_A]
    assert diff.modified == []


def test_diff_modified_requires_same_detector():
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_B, "GitHub Token", "a.txt", 10)])

    diff = diff_scans(current, baseline)

    assert [c.ignore_sha for c in diff.new] == [SHA_B]
    assert [c.ignore_sha for c in diff.removed] == [SHA_A]


def test_diff_modified_requires_same_file():
    baseline = _baseline_from_specs([(SHA_A, "AWS Key", "a.txt", 10)])
    current = _baseline_from_specs([(SHA_B, "AWS Key", "b.txt", 10)])

    diff = diff_scans(current, baseline)

    assert [c.ignore_sha for c in diff.new] == [SHA_B]
    assert [c.ignore_sha for c in diff.removed] == [SHA_A]


def test_diff_mixed_scenario():
    """unchanged moved + new + modified + removed all at once."""
    baseline = _baseline_from_specs(
        [
            (SHA_A, "AWS Key", "a.txt", 10),  # moves line
            (SHA_B, "AWS Key", "c.txt", 4),  # content changes in place
            (SHA_C, "GitHub Token", "gone.txt", 1),  # cleaned away
        ]
    )
    current = _baseline_from_specs(
        [
            (SHA_A, "AWS Key", "a.txt", 20),  # same secret, shifted line
            (SHA_D, "AWS Key", "c.txt", 4),  # rotated value at the same spot
            (SHA_E, "AWS Key", "brand-new.txt", 8),  # genuinely new content
        ]
    )

    diff = diff_scans(current, baseline)

    # SHA_A moved line, SHA_E is new, SHA_D replaced SHA_B's old occurrence at
    # c.txt (modified), SHA_C was cleaned away.
    assert [c.ignore_sha for c in diff.unchanged] == [SHA_A]
    assert diff.unchanged[0].relocated is True

    (modified,) = diff.modified
    assert modified.ignore_sha == SHA_D
    assert modified.previous_shas == [SHA_B]
    assert modified.previous_locations == [FindingLocation("c.txt", 4, 4)]

    assert [c.ignore_sha for c in diff.new] == [SHA_E]
    assert [c.ignore_sha for c in diff.removed] == [SHA_C]


#
# Baseline extraction from a live scan
#


def _build_scan() -> SecretScanCollection:
    result = Result.from_scan_result(
        StringScannable(
            content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            url="leak.txt",
            filemode=Filemode.NEW,
        ),
        scan_result=deepcopy(TWO_POLICY_BREAKS),
        secret_config=SecretConfig(),
    )
    return SecretScanCollection(
        id="scan",
        type="test",
        results=Results(results=[result], errors=[]),
    )


def test_baseline_from_scan_uses_content_hashes():
    scan = _build_scan()
    result = list(scan.get_all_results())[0]
    expected_shas = set(group_secrets_by_ignore_sha(result.secrets))

    baseline = Baseline.from_scan(scan)

    assert set(baseline.incidents) == expected_shas
    for incident in baseline.incidents.values():
        assert incident.locations
        assert all(location.path for location in incident.locations)


#
# Output handler integration
#


def test_handler_exit_code_zero_when_only_known_findings():
    scan = _build_scan()
    baseline = Baseline.from_scan(scan)

    handler = SecretTextOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=baseline
    )
    assert handler.process_scan(scan) == 0


def test_handler_exit_code_one_for_new_finding():
    scan = _build_scan()
    handler = SecretTextOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=Baseline({})
    )
    assert handler.process_scan(scan) == 1


def test_text_handler_sections_with_baseline():
    scan = _build_scan()
    result = list(scan.get_all_results())[0]
    # Compute shas before rendering censors the secret contents
    expected_sha_prefixes = [
        sha[:8] for sha in group_secrets_by_ignore_sha(result.secrets)
    ]
    baseline = Baseline.from_scan(scan)
    # Add a finding that used to exist but is gone
    baseline.incidents["0" * 64] = BaselineIncident(
        "0" * 64, "Old Detector", [FindingLocation("gone.txt", 7, 7)]
    )

    handler = SecretTextOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=baseline
    )
    output = handler._process_scan_impl(scan)

    assert "No new secrets have been found" in output
    assert "Secrets already present in the baseline" in output
    assert "Secrets removed since the baseline scan" in output
    assert "Old Detector" in output
    assert "gone.txt:7" in output
    assert "Baseline summary: 0 new, 0 modified, 2 already present" in output
    assert "1 removed" in output
    # The finding shas from the live scan are displayed compactly
    for prefix in expected_sha_prefixes:
        assert prefix in output


ANSI_ESCAPES = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return ANSI_ESCAPES.sub("", text)


def test_text_handler_new_findings_rendered_in_full():
    scan = _build_scan()
    handler = SecretTextOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=Baseline({})
    )
    output = _plain(handler._process_scan_impl(scan))

    assert "New secrets since the baseline scan" in output
    assert "Secret detected: RSA Private Key" in output
    assert "Secret detected: SendGrid Key" in output
    assert "Baseline summary: 2 new, 0 modified, 0 already present" in output


def test_text_handler_modified_annotation():
    scan = _build_scan()
    # A previous SendGrid finding at leak.txt line 10 whose content differs:
    # the current SendGrid secret is then reported as modified.
    baseline = Baseline(
        {
            "1"
            * 64: BaselineIncident(
                "1" * 64,
                "SendGrid Key",
                [FindingLocation("leak.txt", 10, 10)],
            )
        }
    )

    handler = SecretTextOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=baseline
    )
    output = handler._process_scan_impl(scan)

    assert "secret content changed since the baseline scan" in output
    assert "11111111 at leak.txt:10" in output
    assert "Baseline summary: 1 new, 1 modified" in output


def test_json_handler_baseline_annotations():
    scan = _build_scan()
    baseline = Baseline.from_scan(scan)
    baseline.incidents["0" * 64] = BaselineIncident(
        "0" * 64, "Old Detector", [FindingLocation("gone.txt", 7, 7)]
    )

    handler = SecretJSONOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=baseline
    )
    report = json.loads(handler._process_scan_impl(scan))

    assert report["baseline"] == {
        "path": None,
        "new_incidents": 0,
        "modified_incidents": 0,
        "unchanged_incidents": 2,
        "removed_incidents": 1,
    }
    statuses = [
        incident["baseline_status"]
        for result in report["entities_with_incidents"]
        for incident in result["incidents"]
    ]
    assert statuses == ["unchanged", "unchanged"]
    assert report["removed_incidents"] == [
        {
            "ignore_sha": "0" * 64,
            "detector": "Old Detector",
            "occurrences": [{"filename": "gone.txt", "line_start": 7, "line_end": 7}],
        }
    ]


def test_json_handler_new_finding_annotated():
    scan = _build_scan()
    handler = SecretJSONOutputHandler(
        verbose=False, secret_config=SecretConfig(), baseline=Baseline({})
    )
    report = json.loads(handler._process_scan_impl(scan))

    statuses = [
        incident["baseline_status"]
        for result in report["entities_with_incidents"]
        for incident in result["incidents"]
    ]
    assert statuses == ["new", "new"]
    assert report["baseline"]["new_incidents"] == 2


def test_json_report_without_baseline_has_no_baseline_fields():
    scan = _build_scan()
    handler = SecretJSONOutputHandler(verbose=False, secret_config=SecretConfig())
    report = json.loads(handler._process_scan_impl(scan))
    assert "baseline" not in report
    assert "removed_incidents" not in report
