### Security

- `ggshield secret scan archive` now checks the archive metadata before
  unpacking it and refuses archives whose total uncompressed size, number of
  files or maximum path depth exceed the limits (1 GiB, 10,000 files and 200
  path components by default). The error message lists every limit that was
  exceeded. The limits can be overridden with the `GG_ARCHIVE_MAX_TOTAL_SIZE`,
  `GG_ARCHIVE_MAX_FILE_COUNT` and `GG_ARCHIVE_MAX_PATH_DEPTH` environment
  variables. This prevents a deeply nested or highly compressible ("archive
  bomb") archive from filling the temporary disk.

### Changed

- When scanning an archive, a single member whose data cannot be read (for
  example a corrupted entry) is skipped instead of aborting the whole scan;
  the other members are still scanned. The unpacked content is always removed
  from the temporary directory, whether the scan succeeds or fails.
- A scan which could not scan all its input files now exits with the new exit
  code 5 ("scan incomplete") when no secret was found, so it can no longer be
  confused with a successful scan which found no secret. The skipped files are
  listed in the text output and, with `--json`, in a new top-level
  `incomplete` field.
