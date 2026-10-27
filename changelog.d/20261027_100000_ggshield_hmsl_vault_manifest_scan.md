### Changed

- `ggshield hmsl check-secret-manager hashicorp-vault` now enumerates the
  paths to check and their versions before fetching any content, and reads
  every secret against this manifest. Paths added, deleted or modified while
  the scan is running are re-read once or reported as not checked, and paths
  the token cannot read are listed separately instead of being silently
  skipped. The command now exits with a non-zero status unless the whole
  manifest was checked against a stable version.
