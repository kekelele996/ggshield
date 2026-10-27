### Fixed

- `ggshield machine setup` now installs the AI assistant hooks all-or-nothing:
  every assistant's settings file is checked, merged and rendered in memory
  first, and all targets are written only when every one of them can be
  updated. Previously, an unparseable or unwritable settings file for the
  second assistant left the first assistant's file modified and the remaining
  assistants untouched. A failure while writing now rolls every already-written
  file back to its previous bytes, each failing assistant and settings file is
  named in the output, and re-running the command no longer adds a second
  ggshield entry next to the first one.
