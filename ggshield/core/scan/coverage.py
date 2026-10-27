"""
Coverage tracking of a scan.

A `ScanCoverage` instance records every file the scan pipeline saw: either as
scanned (its content was sent to the scanning engine) or as not checked,
classified by a single `SkipReason`. A file is classified only once: the first
stage of the pipeline which decides a file cannot be scanned wins, so counts
can never add up to more than the number of files found.
"""

from enum import Enum
from typing import Dict, List, Tuple


class SkipCategory(str, Enum):
    """High-level reason why a file was not checked."""

    RULES = "rules"
    READ_ERROR = "read_error"
    CONTENT = "content"


class SkipReason(str, Enum):
    """Precise reason why a file was not checked.

    Each member is a ``(api value, category, human-readable label)`` tuple.
    """

    # Rules / configuration
    EXCLUDED_PATH = (
        "excluded_path",
        SkipCategory.RULES,
        "path matches an exclusion rule",
    )
    GITIGNORED = ("gitignored", SkipCategory.RULES, "ignored by git (.gitignore)")

    # Read errors
    FILE_NOT_FOUND = ("file_not_found", SkipCategory.READ_ERROR, "file not found")
    NON_SEEKABLE = (
        "non_seekable",
        SkipCategory.READ_ERROR,
        "file cannot be seeked",
    )

    # Content restrictions
    BINARY = ("binary", SkipCategory.CONTENT, "binary file")
    TOO_LARGE = (
        "too_large",
        SkipCategory.CONTENT,
        "file content is over the size limit",
    )
    PAYLOAD_LIMIT = (
        "payload_limit",
        SkipCategory.CONTENT,
        "encoded content is over the request payload limit",
    )
    ENCODING = (
        "encoding",
        SkipCategory.CONTENT,
        "unable to detect the file encoding",
    )
    EMPTY = ("empty", SkipCategory.CONTENT, "empty file")

    _category: SkipCategory
    _label: str

    def __new__(cls, value: str, category: SkipCategory, label: str) -> "SkipReason":
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj._category = category
        obj._label = label
        return obj

    @property
    def category(self) -> SkipCategory:
        return self._category

    @property
    def label(self) -> str:
        return self._label


# Display order of categories and their reasons
CATEGORY_ORDER = [
    SkipCategory.RULES,
    SkipCategory.READ_ERROR,
    SkipCategory.CONTENT,
]

CATEGORY_LABELS = {
    SkipCategory.RULES: "excluded by rules",
    SkipCategory.READ_ERROR: "read errors",
    SkipCategory.CONTENT: "content restrictions",
}


class ScanCoverage:
    """Records which files were scanned and which were not checked, and why."""

    def __init__(self) -> None:
        self.scanned_files: List[str] = []
        self._skipped_files: Dict[SkipReason, List[str]] = {
            reason: [] for reason in SkipReason
        }
        # A file is classified once, at the first stage which drops it
        self._seen: set[str] = set()

    def record_scanned(self, name: str) -> None:
        """Record a file whose content was actually checked."""
        if name in self._seen:
            return
        self._seen.add(name)
        self.scanned_files.append(name)

    def record_skipped(self, reason: SkipReason, name: str) -> None:
        """Record a file which was not checked, classified by `reason`.

        The first recorded reason for a file wins, matching the order of the
        scan pipeline (file listing, then file reading and scanning).
        """
        if name in self._seen:
            return
        self._seen.add(name)
        self._skipped_files[reason].append(name)

    def skipped_files(self, reason: SkipReason) -> List[str]:
        """Return the files recorded as skipped for `reason`."""
        return self._skipped_files[reason]

    def reasons_for(
        self, category: SkipCategory
    ) -> List[Tuple["SkipReason", List[str]]]:
        """Return ``[(reason, files), ...]`` for the non-empty reasons of
        `category`, in the enum declaration order."""
        return [
            (reason, self._skipped_files[reason])
            for reason in SkipReason
            if reason.category == category and self._skipped_files[reason]
        ]

    @property
    def scanned_count(self) -> int:
        return len(self.scanned_files)

    @property
    def skipped_count(self) -> int:
        return sum(len(files) for files in self._skipped_files.values())

    def skipped_count_for(self, category: SkipCategory) -> int:
        return sum(
            len(self._skipped_files[reason])
            for reason in SkipReason
            if reason.category == category
        )

    @property
    def total_count(self) -> int:
        return self.scanned_count + self.skipped_count

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serializable representation of the coverage,
        including the complete list of files so specific files can be located
        without digging through logs."""
        categories: List[Dict[str, object]] = []
        for category in CATEGORY_ORDER:
            reasons = [
                {
                    "name": reason.value,
                    "label": reason.label,
                    "count": len(files),
                    "files": list(files),
                }
                for reason, files in self.reasons_for(category)
            ]
            categories.append(
                {
                    "name": category.value,
                    "label": CATEGORY_LABELS[category],
                    "count": self.skipped_count_for(category),
                    "reasons": reasons,
                }
            )
        return {
            "total_files": self.total_count,
            "scanned_files": self.scanned_count,
            "scanned": list(self.scanned_files),
            "skipped_files": self.skipped_count,
            "categories": categories,
        }
