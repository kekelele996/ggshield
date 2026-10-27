### Added

- `ggshield secret scan path` and `ggshield secret scan repo` now accept
  `--baseline PATH` to compare the scan with a JSON report saved by a previous
  run. Findings already in the baseline are no longer reported as new, even
  when they moved to another file or line; new findings, findings whose
  content changed and findings removed since the baseline are listed
  separately. The command exits with a non-zero status only when new or
  modified findings are found. `--save-baseline PATH` saves the complete JSON
  report of the current scan for later use as a baseline.
