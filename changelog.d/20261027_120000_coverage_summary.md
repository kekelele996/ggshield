### Added

- `ggshield secret scan path` now ends with a coverage summary: it counts the
  files it scanned and the files it did not check, split between rules
  (exclusion patterns, .gitignore), read errors (missing or unseekable files)
  and content restrictions (binary, empty, undecodable or too large files).
  Each file is attributed to a single reason. File names are listed in verbose
  mode, and the JSON output always contains the complete file lists, so a scan
  can be audited without reading debug logs. Findings and exit codes are
  unchanged.
