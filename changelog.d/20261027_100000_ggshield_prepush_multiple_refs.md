### Fixed

- The `secret scan pre-push` hook now takes into account every ref update of a
  push (multiple branches, tags, mirror pushes) instead of scanning only the
  first line of the hook stdin: deleted refs are reported and skipped, commits
  shared by several refs are only scanned once, the check result is reported
  per ref, and any ref introducing a secret now blocks the whole push.
