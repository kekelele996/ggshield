import pytest

from ggshield.core.scan.coverage import (
    CATEGORY_ORDER,
    ScanCoverage,
    SkipCategory,
    SkipReason,
)


def test_scanned_and_skipped_counts():
    coverage = ScanCoverage()
    coverage.record_scanned("a")
    coverage.record_scanned("b")
    coverage.record_skipped(SkipReason.BINARY, "c")
    coverage.record_skipped(SkipReason.TOO_LARGE, "d")

    assert coverage.scanned_count == 2
    assert coverage.skipped_count == 2
    assert coverage.total_count == 4
    assert coverage.scanned_files == ["a", "b"]


def test_file_is_classified_only_once_first_reason_wins():
    """
    GIVEN a file recorded at one pipeline stage
    WHEN the same file is recorded again at a later stage
    THEN only the first classification is kept
    """
    coverage = ScanCoverage()

    coverage.record_skipped(SkipReason.BINARY, "f")
    coverage.record_skipped(SkipReason.TOO_LARGE, "f")
    coverage.record_scanned("f")

    assert coverage.skipped_files(SkipReason.BINARY) == ["f"]
    assert coverage.skipped_files(SkipReason.TOO_LARGE) == []
    assert coverage.scanned_files == []
    assert coverage.total_count == 1


def test_scanned_after_classification_is_ignored():
    coverage = ScanCoverage()
    coverage.record_scanned("f")
    coverage.record_skipped(SkipReason.EMPTY, "f")
    assert coverage.scanned_files == ["f"]
    assert coverage.skipped_count == 0


def test_reasons_group_by_category():
    coverage = ScanCoverage()
    coverage.record_skipped(SkipReason.EXCLUDED_PATH, "a")
    coverage.record_skipped(SkipReason.GITIGNORED, "b")
    coverage.record_skipped(SkipReason.FILE_NOT_FOUND, "c")
    coverage.record_skipped(SkipReason.NON_SEEKABLE, "d")
    coverage.record_skipped(SkipReason.BINARY, "e")
    coverage.record_skipped(SkipReason.ENCODING, "f")
    coverage.record_skipped(SkipReason.EMPTY, "g")
    coverage.record_skipped(SkipReason.TOO_LARGE, "h")
    coverage.record_skipped(SkipReason.PAYLOAD_LIMIT, "i")

    assert coverage.skipped_count_for(SkipCategory.RULES) == 2
    assert coverage.skipped_count_for(SkipCategory.READ_ERROR) == 2
    assert coverage.skipped_count_for(SkipCategory.CONTENT) == 5

    reasons = [reason for reason, files in coverage.reasons_for(SkipCategory.CONTENT)]
    assert reasons == [
        SkipReason.BINARY,
        SkipReason.TOO_LARGE,
        SkipReason.PAYLOAD_LIMIT,
        SkipReason.ENCODING,
        SkipReason.EMPTY,
    ]


def test_every_reason_belongs_to_a_known_category():
    for reason in SkipReason:
        assert reason.category in SkipCategory
        assert reason.label


def test_category_order_covers_all_categories():
    assert set(CATEGORY_ORDER) == set(SkipCategory)


def test_to_dict_is_json_ready_and_complete():
    coverage = ScanCoverage()
    coverage.record_scanned("a")
    coverage.record_skipped(SkipReason.EXCLUDED_PATH, "b")

    data = coverage.to_dict()
    assert data["total_files"] == 2
    assert data["scanned_files"] == 1
    assert data["scanned"] == ["a"]
    assert data["skipped_files"] == 1

    rules = next(c for c in data["categories"] if c["name"] == "rules")
    assert rules["count"] == 1
    reason = rules["reasons"][0]
    assert reason["name"] == "excluded_path"
    assert reason["count"] == 1
    assert reason["files"] == ["b"]

    # Empty categories are still listed, with stable order
    assert [c["name"] for c in data["categories"]] == [c.value for c in CATEGORY_ORDER]

    import json

    json.dumps(data)


@pytest.mark.parametrize(
    "reason,expected_category",
    [
        (SkipReason.EXCLUDED_PATH, SkipCategory.RULES),
        (SkipReason.GITIGNORED, SkipCategory.RULES),
        (SkipReason.FILE_NOT_FOUND, SkipCategory.READ_ERROR),
        (SkipReason.NON_SEEKABLE, SkipCategory.READ_ERROR),
        (SkipReason.BINARY, SkipCategory.CONTENT),
        (SkipReason.TOO_LARGE, SkipCategory.CONTENT),
        (SkipReason.PAYLOAD_LIMIT, SkipCategory.CONTENT),
        (SkipReason.ENCODING, SkipCategory.CONTENT),
        (SkipReason.EMPTY, SkipCategory.CONTENT),
    ],
)
def test_reason_categories(reason, expected_category):
    assert reason.category == expected_category
