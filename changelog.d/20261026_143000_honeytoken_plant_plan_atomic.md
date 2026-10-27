### Added

- `ggshield honeytoken plant` is now two-phase and all-or-nothing: it first stages
  every target read-only and prints a placement plan naming the account/profile or
  cluster/context each honeytoken belongs to (and the other identities already
  sharing each file), then commits the whole group at once after confirmation.
  `--plan` prints the plan and exits without writing or confirming anything, and
  `--yes` skips the confirmation prompt for non-interactive runs. If any target
  conflicts, is unreadable, or changes between the plan and the commit, no file is
  modified and earlier files are rolled back. Entries already in place are skipped,
  so re-running the command never plants a second copy.
