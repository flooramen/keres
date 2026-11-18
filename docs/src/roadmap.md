# Roadmap

Security-first priorities, derived from the [Known Limitations](security.html) and from audit findings. Items are grouped by horizon; within
a group they are roughly priority-ordered. Anything that weakens a security
property will never be accepted for a compatibility or convenience win.

## Now (next release)

- **Fuzzing targets** — `cargo-fuzz` harnesses for `read_container`,
  `read_entry`, manifest/config parsing and name sanitization. The parser
  surface is small; it should be provably robust against hostile input.
  *(Done: `fuzz/` covers the container, manifest, config, and sanitizer
  parsers, with a seeded corpus and a weekly workflow.)*
- **Published test vectors and benchmarks** — a committed deterministic
  `.krs` fixture with a pinned SHA-256, plus Criterion throughput benches.
  *(Done.)*
- **Memory locking** — evaluate `memsec`/`region` behind a tiny `unsafe`
  boundary (feature-gated) so master keys can be `mlock`ed and core dumps
  suppressed. Requires relaxing `forbid(unsafe_code)` to
  `deny(unsafe_code)` with audited allow-lists.
- **Rollback protection (limitation 6)** — store a MAC'd monotonically
  increasing generation counter in the vault config and sign each manifest
  save with it, so restoring an old snapshot of the vault directory is at
  least *detectable* on next unlock.
- **Stable entry identity** — blobs and container AAD are keyed by a random
  128-bit entry ID stored in the manifest, not by the mutable path, so
  `rename` rewrites only the manifest. *(Done. Manifest v3; `Vault::rename` /
  `keres rename`. Manifest scaling and rollback protection remain.)*
- **Concurrent-access safety** — non-blocking advisory locks around every
  vault read and write, so a second process fails fast with `VaultBusy`
  instead of clobbering the manifest. *(Done.)*
- **CI hardening** — Windows and macOS test jobs are in place, and
  `cargo-deny` gates advisories, licenses, and sources. A tag-driven
  `release.yml` now publishes both crates via Trusted Publishing and attaches
  attested binary archives; remaining work is enabling the crates.io trusted
  publishers and the protected `release` environment.

## Next (0.6.x)

- **v2 → v3 vault migration** — 0.5.0 vaults use manifest v2 and are
  rejected by the v3 reader. *(Done. `Vault::migrate` / `keres migrate`
  re-encrypts each entry under a fresh ID, commits the v3 manifest atomically,
  then removes the legacy blobs; the reader reports `MigrationRequired`.)*
- **Recovery kit** — printable recovery code that wraps the master key under
  a second Argon2id-derived key, stored alongside `vault.config`. *(Done.
  `Vault::create_recovery_kit` / `keres recovery create`; `Vault::recover`
  recreates a lost config, validates the key against the index, and consumes
  the kit.)*
- **Multiple keyslots (LUKS-style)** — several independent passphrases per
  vault, each its own wrapped copy of the master key; individual slots can be
  revoked. *(Done. Config v3 stores a slot table; `Vault::add_keyslot` /
  `remove_keyslot` and `keres keyslot add|remove|list`; v2 configs upgrade on
  the next key change.)*
- **Content re-encryption on password change (limitation 2)** — optional
  deep rotation: derive a fresh master key and stream every blob through
  re-encryption. *(Done. `Vault::rotate` / `keres rotate`; crash-safe via
  the `vault.rotate` journal, collapses to one keyslot and removes the
  recovery kit.)*
- **Parallel chunk pipeline** — encrypt/decrypt chunks across threads
  (counter nonces and AAD already make chunks independent). Target:
  saturate AES-NI (~3–5 GB/s) instead of today's ~400 MB/s single-thread.
- **Streaming public API** — `Read`/`Write` adapter types so library users
  can pipe containers without buffering whole objects. *(Done.
  `keres::streaming::{EncryptWriter, DecryptReader, encrypt_stream,
  decrypt_stream}` with progress and cancellation.)*
- **Orphan garbage collection** — after failed adds/removals, blobs may
  exist that no manifest record references. `verify --prune` /
  `Vault::prune_orphans` walks `d/` and deletes unreferenced blobs and stale
  temp files. *(Done.)*
- **Dependency slimming: drop `walkdir`** — its single production use is
  the directory traversal in `add_directory_tree` (`crates/keres/src/vault/mod.rs`).
  Replace with a ~40-line `std::fs::read_dir` walker preserving exact
  semantics (pre-order, siblings sorted by file name, parents before
  children, symlinks and special files skipped). Removes `walkdir` and
  `same-file` from every consumer's build. Pure hygiene win; existing
  nested-directory tests guard against behavior drift. Considered and
  rejected for now to avoid touching a verified codebase.

## Next (0.7.x)

- **Append-only encrypted index** — stop rewriting the whole manifest on every
  mutation. *(Done. Snapshot plus `d/.index.log`: authenticated `put`/`delete`
  batches, per-log keys, snapshot/generation binding, 512-record or 8 MiB
  compaction, and journaled compaction recovery.)*
- **Group commit** — coalesce concurrent writers into one durable batch so a
  busy vault pays for one `sync_data` per group rather than per mutation.
- **Index generations** — carry a monotonic generation in the snapshot/log
  header and require them to agree, so replace and compaction swaps are
  unambiguous. *(Internal generations done; snapshots authenticate the
  generation and compaction advances it.)* Turning the counter into actual
  rollback detection still needs hardware-backed state (limitation 6).
- **L2+ metadata protection** — pad entry sizes to fixed buckets, coarsen
  observable timing, and optionally bucket mutation counts. Explicit
  non-goals: access-pattern hiding, exact-count hiding, and deniability.

## Later (1.0 candidates)

- **Hardware-backed keys** — optional second factor via OS key stores
  (TPM, Secure Enclave, FIDO2/hmac-secret) combined with the password
  (limitation 4). Must remain strictly optional; plain password vaults are
  the default and always supported.
- **Size hiding (limitation 5)** — optional fixed-size padding buckets
  for `.krs` output and/or random trailing padding before the end marker,
  trading space for length privacy. Needs care: padding must be covered by
  the trailer's authenticated `size`.
- **External security audit** — pay for a professional review of the
  container format, key hierarchy and implementation before calling 1.0
  production-grade. No amount of internal review substitutes for this.
- **Constant-time decisions** — review any branch on secret material
  (currently none known: all comparisons are inside AEAD verification),
  and document the argument formally in SECURITY.md.

## Explicitly out of scope

- **Plausibility/deniability (limitation 3)** — the magic is a feature;
  hidden-volume schemes conflict with authenticated formats and invite
  user-error catastrophes. Revisit only with a rigorous design.
- **Backward compatibility shims** — only the current format is accepted.
  The single exception is the one-way v2 → v3 vault upgrade in
  `keres migrate`; there is no ongoing reader support for old formats.

