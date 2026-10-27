### Added

- `ggshield secret scan repo` and `ggshield secret scan commit-range` now keep
  track of the batches already scanned for each repository, scan scope and
  configuration. If a scan is interrupted (network outage, quota limit,
  machine restart…), running it again only scans the commits that were not
  processed yet, instead of starting over from the oldest commit and spending
  the API quota again. Commits whose batch previously failed are retried.
  Changing the scan range or the configuration invalidates the matching
  progress, so new content is never skipped with stale state. When a run
  resumes, its output reports how many already scanned commits were skipped
  and how many previously failed commits were retried.
