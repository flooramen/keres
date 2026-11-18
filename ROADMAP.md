# Roadmap

The detailed, security-first roadmap lives in
[`docs/src/roadmap.md`](docs/src/roadmap.md). This page tracks the work that
matters most for the monorepo.

## Now

- [x] Consolidate the core, CLI, and documentation into one workspace.
- [x] Vault-level file locking (`flock`) so concurrent processes cannot
      clobber the manifest.
- [x] Cross-platform CI (Windows and macOS) and an atomic replace path for
      Windows.
- [x] Fuzzing for container, manifest, and config parsers.
- [x] `cargo-deny` supply-chain checks.
- [ ] Signed release artifacts (workflow now publishes via Trusted
      Publishing and attests binaries; enable the `release` environment and
      crates.io trusted publishers before the first tag).
- [x] Published test vectors for the container format.
- [x] Criterion benchmarks for the container pipeline.

## Next

- [x] `keres migrate`: re-encrypt 0.5.0 (manifest v2) vaults into v3 in place
      (stable IDs, atomic manifest cut-over, legacy blobs removed).
- [x] Decouple entry identity from the mutable path (stable random IDs), so
      `rename` does not require re-encryption.
- [x] Public streaming API (`Read`/`Write` adapters), progress, and
      cancellation (`keres::streaming`, `EncryptWriter`/`DecryptReader`).
- [ ] Entry metadata (mtime, mode) and `list --recursive` / `stat`.
- [x] Printable recovery kit (`keres recovery create` / `recovery use`,
      `Vault::create_recovery_kit` / `Vault::recover`).
- [x] LUKS-style keyslots (`Vault::add_keyslot` / `remove_keyslot`,
      `keres keyslot add|remove|list`; config v3 slot table).
- [x] Opt-in deep rotation (`Vault::rotate` / `keres rotate`): fresh master
      key, every entry re-encrypted, journal-based crash recovery; collapses
      to one keyslot and removes the recovery kit.
- [ ] Multi-recipient keys (X25519).
- [x] Orphan garbage collection (`verify --prune`).
- [x] Append-only encrypted index log with snapshot compaction, journaled
      crash recovery, and automatic journal recovery on lock acquisition.
- [ ] Size padding to buckets and operation-count bucketing (L2+).
- [ ] Parallel chunk pipeline.

## Later

- [ ] Optional size-hiding padding buckets.
- [ ] Snapshot/version history and restore.
- [ ] Hardware-backed keys (TPM, Secure Enclave, FIDO2).
- [ ] External security audit and a 1.0 release.

## Out of scope

- Plausible deniability / hidden volumes.
- Backwards-compatible readers for pre-0.4 formats.
