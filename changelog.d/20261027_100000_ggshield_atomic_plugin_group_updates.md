### Security

- `ggshield plugin update` now applies multi-package upgrades atomically: all
  wheels, signature bundles and trust material are downloaded and verified in
  a hidden staging area before any installed plugin is touched. A network
  failure or a signature/checksum failure on any single package now keeps the
  entire group on its previous versions instead of leaving new and old files
  mixed on disk. A journal makes the final switch crash-safe — an interrupted
  upgrade is automatically rolled back (or completed) on the next startup, so
  a half-swapped (and potentially unsigned) plugin can no longer be loaded.

### Changed

- Successful `plugin update` runs finish with an "Updated N plugins as a
  group" summary listing every package that changed with its old and new
  version.
