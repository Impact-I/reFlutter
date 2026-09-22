### Helper Scripts

1. `build-engine` -> Script to build custom flutter engine (macOS)
2. `gen_enginehash.py` -> To dump all flutter engine and app hashes in a file.
   Resumes from previous output, so re-runs only fetch missing rows.
   Flags: `--out CSV`, `--seed CSV` (repeatable), `--workers N`, `--limit N`.
3. `get_flutter_engine.py` -> Get flutter engine hash from a Flutter engine binary.
4. `get_snapshot_hash.py` -> Get app hash from `App` or `libapp.so` file.
5. `local-release` -> Build + upload patched engines (v2/v3, iOS + Android
   arm64/arm/x64) for the hash in `../SNAPSHOT_HASH`. Verifies every patch
   anchored before building and aborts on drift. Flags: `--v2-only`,
   `--v3-only`, `--build-only`, `--upload-only`.
