# Architecture

## Cryptographic primitives

All primitives come from RustCrypto crates (`aes-gcm`, `argon2`, `hkdf`,
`sha2`, `subtle`) with randomness from the OS CSPRNG (`OsRng`).

| Primitive | Parameters | Used for |
|---|---|---|
| AES-256-GCM | 96-bit nonces, 128-bit tags | every byte of ciphertext |
| Argon2id | default m=64 MiB, t=4, p=4 (stored in-container) | password → KEK |
| HKDF-SHA256 | random 32-byte salt per object | master/subkey separation |
| SHA-256 | — | blob location hashing only (not secret-derived output exposure) |
| `subtle::ConstantTimeEq` | — | comparisons on secret material |

### KDF parameter bounds (`KdfParams`)

Parameters travel inside containers so defaults can evolve. Because they
are attacker-visible input, parsing enforces hard bounds to prevent
denial-of-service:

| Field | Default | Accepted range when reading |
|---|---|---|
| `m_cost_kib` | 65 536 (64 MiB) | 8 MiB … 4 GiB |
| `t_cost` | 4 | 1 … 64 |
| `p_cost` | 4 | 1 … 16 |

A hostile file can therefore force at most ~minutes of derivation work —
never unbounded allocation or infinite loops.

---

## Key hierarchy

Two independent derivations exist, selected per container by a kind byte:

```
Standalone .krs (kind = password):

  password ──Argon2id(argon_salt, params)──► KEK ──HKDF(object_salt)──► content key

Vault objects (kind = hkdf):

  vault.config: password ──Argon2id(salt, kdf)──► KEK ──AES-GCM-wrap──► master key
                                                                     │
        entry blob ──HKDF(master, object_salt, info‖entry_id)────────┤
        manifest   ──HKDF(master, object_salt, info‖"vault-manifest")─┘
```

Properties that follow:

- **Per-object keys.** Every object's content key differs, even under the
  same password/master: salts are fresh random 32-byte values, and the
  HKDF `info` includes a location identity (§5.4).
- **Password change never touches ciphertext.** Only the wrapped copy of
  the master key in `vault.config` is re-encrypted.
- **No offline verifier.** There is no hash to check guesses against;
  every guess costs one full Argon2id run plus GCM verification.

---

## The universal container format

Every object the library produces — `.krs` files, vault blobs, manifests —
is one envelope. Defined in `crates/keres/src/container.rs`; constants are public where
meaningful (`MAGIC`, `ENVELOPE_VERSION`).

### Wire layout

```text
offset  size                     field
────────────────────────────────────────────────────────────────
0       8    "KERES\0\0\0"          magic (NUL is a control byte:
                                  cannot occur in plain text)
8       2    u16 LE               envelope version (currently 1)
10      1    kind                 0 = HKDF-from-master
                                  1 = password-derived
11      32   (kind 0)             object_salt
11      76   (kind 1)             argon_salt[32] ‖ object_salt[32]
                                  ‖ KdfParams[12] (three u32 LE)
…       var  chunk records         [len u32 LE][ciphertext‖tag], repeated
…       4    00 00 00 00          end-of-chunks marker (unauthenticated;
                                  safe — see §6.3)
…       4    len u32 LE           trailer length (≤ 1 MiB enforced)
…       len  trailer              AES-GCM ct‖tag of JSON (§5.3)
```

Header sizes: 43 bytes (kind 0) or 87 bytes (kind 1).

### Header authentication strategy

No separate header MAC is needed. The header is authenticated **implicitly**:
the magic and version are checked directly, while the kind, salts, and KDF
parameters feed key derivation. Flipping any of those bytes yields a wrong
key or an early parse error, so the first GCM tag check fails.

Any file whose magic is not exactly `KERES\0\0\0` is rejected with
`IncompatibleFormat`. That includes pre-rename Krypton containers, pre-0.4
Krypton formats, and unrelated files. Only the current Keres format is
accepted; extract old data with the release that wrote it. A header with the
right magic but a newer envelope version fails early with
`UnsupportedVersion(v)`. Vaults are the one exception: a readable 0.5.x vault
manifest is reported as `MigrationRequired` and upgraded by `keres migrate`.

### Trailer

After the chunk section, one final record carries a JSON document sealed
with the same content key under the reserved nonce `[0xFF; 12]`:

```json
{
  "typ": "file" | "directory" | "manifest",
  "name": "original-filename.txt",   // .krs only, optional
  "size": 12345,                      // total plaintext length
  "chunk_count": 1                    // number of preceding records
}
```

On read, the trailer is cross-checked against observation: `typ` must
equal the caller-requested payload type, `size` must equal decrypted byte
count, `chunk_count` must equal records seen, and **nothing may follow the
trailer**. Truncation, extension, and appended-junk attacks all fail here
even if a naive reader would have accepted the prefix.

### Identity binding

Containers carry a caller-supplied *identity* string that participates in
key derivation (`info = "keres-container-v1/" ‖ identity`) :

| Object | Identity | Effect |
|---|---|---|
| Vault entry blob | stable random entry ID, e.g. `"00112233…"` | copying one entry's blob over another's slot fails authentication; renaming does not invalidate a blob |
| Manifest | `"vault-manifest"` | fixed constant; manifest location is canonical |
| Standalone `.krs` | empty | files are self-contained; nothing to bind |

Each entry gets a 128-bit random ID when it is added. The ID is stored in the
manifest and never changes, so the blob location and AAD are independent of
the entry's mutable path. This closes the *blob-transplant* attack class
entirely: an attacker who swaps two blobs in the vault directory gets
`Corrupted` reports from `verify()` and errors on extract — never silently
wrong content.

### Payload types

`PayloadType` has three variants today. Adding new container kinds (future
metadata sidecars or keyslots) means adding a variant with a new AAD context
string — **never** changing existing ones. This is the core reason the format
can evolve without a format zoo.

---

## Chunking, nonces and AAD binding

`crates/keres/src/stream.rs` implements record framing shared by all containers.

### Chunk records

Plaintext streams through in **64 KiB** chunks (`CHUNK_SIZE`). Each becomes
one record: `[len u32 LE][ciphertext ‖ 16-byte GCM tag]`. Lengths outside
`16 ..= 64 KiB + 16` are rejected before allocation (no decompression-bomb
analog possible; there is no compression).

Maximum object size: `2^24 chunks × 64 KiB = 1 TiB` (`MAX_CHUNK_COUNT`
guard prevents nonce-space exhaustion and counter overflow).

### Nonce strategy

| Record type | Nonce | Rationale |
|---|---|---|
| Data chunk *i* | `[0x00 ×8 ‖ i as u64 BE]` | counter-based: collision-free within an object regardless of restarts |
| Trailer | `[0xFF; 12]` | reserved domain, distinct from data |
| vault.config | `[0x01, 0xFF ×11]` | fixed, safe: unique KEK per vault, message written once ever |
| Manifest/config wraps | fixed nonce + fresh random content key each write | key rotation substitutes for nonce uniqueness |

(The chunk nonce is `n[4..] = index.to_be_bytes()` — eight zero prefix,
eight-byte big-endian counter; the trailer and config nonces are chosen to
never collide with any possible counter value.)

Counter nonces eliminate the birthday-bound reuse risk that plagues
random-nonce-per-chunk designs (the pre-0.3 weakness). Combined with
per-object salts they give every (object, position) pair a unique
(key, nonce) tuple.

### AAD matrix

Every GCM operation binds context. Nothing is ever decrypted "bare":

| Operation | AAD |
|---|---|
| Data chunk *i* | `"keres-container-v1/{file\|directory\|manifest}"` ‖ index bytes |
| Trailer | chunk context ‖ index ‖ `"/trailer"` |
| vault.config wrap | `"keres-vault-config-v2"` |

Consequences:

- Reordering two chunks → tag failure.
- Moving a record between positions → tag failure.
- Moving records between containers of different payload types → tag
  failure (context differs).
- Transplanting whole containers between logical locations → key
  derivation differs (§5.4).
- The end-of-chunks marker is *unauthenticated but harmless*: it cannot be
  forged into extra data because `chunk_count` and `size` in the
  authenticated trailer must match observation exactly.

---

## Single-file mode (.krs)

`encrypt_file(password, input, output)`:

1. Generates fresh `argon_salt` and `object_salt`.
2. Builds a kind-1 container streaming the file (identity = empty),
   storing the original filename in the trailer.
3. Writes atomically: temp file (mode 0600) in the destination directory →
   fsync → rename. On Windows, `rename` replaces the destination via
   `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING`, with no pre-delete window.
4. If no output path is given, produces `<sha256(argon_salt ‖ object_salt
   )>.krs` — a random-looking name leaking nothing about content.

`decrypt_file(password, input, output)` authenticates the whole container
while streaming, recovers the original filename from the trailer, sanitizes
it, and returns it. Plaintext is written via temp+rename as well.

Memory use is bounded by one chunk buffer (+tag) regardless of file size;
multi-gigabyte files stream at constant memory.

### Streaming API

`keres::streaming` exposes the same wire format to library code that does not
have files:

| Type / function | Direction |
|---|---|
| `EncryptWriter` | `Write`: plaintext in, ciphertext out; `finish()` writes the trailer |
| `DecryptReader` | `Read`: ciphertext in, authenticated plaintext out; EOF verifies the trailer |
| `encrypt_stream` / `decrypt_stream` | Convenience loops that keep the typed `Error` |

`StreamOptions` adds a cumulative-byte progress callback and an
`AtomicBool` cancellation flag polled once per chunk. Cancellation returns
`Error::Cancelled`; through the `io` adapters it is wrapped in an
`io::Error`, with the typed error recoverable from its source.

Every chunk is authenticated before its plaintext is yielded, but the trailer
holds the total size and chunk count, so a truncated or trailer-tampered
stream can deliver authenticated plaintext before the final error. File
writers should therefore stage output through temp+rename, exactly as
`decrypt_file` does. This is an inherent property of streaming, not a laxity
in the chunk authentication.

The adapters and functions are format-compatible with `encrypt_file` and
`decrypt_file` in both directions.

---

## Vault mode

A vault is a directory:

```
myvault/
├── vault.config          bootstrap JSON (plaintext structure, sealed value)
├── vault.recovery        optional second wrapping of the master key
├── vault.rotate          transient deep-rotation journal (present only mid-run)
├── vault.lock            advisory inter-process lock (empty)
└── d/
    ├── .manifest.enc     compacted index snapshot, as a kind-0 container
    ├── .index.log        encrypted append-only mutations after the snapshot
    ├── .index.compact    transient index-compaction journal
    ├── .manifest.enc.next  staged manifest during rotation (transient)
    ├── .index.log.next     staged empty log during compaction (transient)
    ├── .index.snapshot.next  staged snapshot during compaction (transient)
    └── <h2>/<h48>.enc    one blob per entry, as kind-0 containers
```

Every mutating operation takes an exclusive advisory lock on `vault.lock`;
read operations (`list`, `extract`, `verify`) take a shared lock. Locks are
non-blocking: a second process gets `Error::VaultBusy` instead of waiting and
risking a stale index. The lock is released when the operation returns.
`flock(2)` is used on Unix and `LockFileEx` on Windows via `fs4`.

If a rotation or an index compaction committed but did not finish (the
process died between its journal write and cleanup), the next operation that
takes the lock recovers it first. A reader that only needs a shared lock
silently upgrades to the exclusive lock for that recovery step.

### vault.config (bootstrap)

A small JSON document — *not* a container, because it must be parseable
before any key exists. Version 3 holds a table of independent keyslots, each
wrapping the *same* master key under its own password-derived KEK:

```json
{
  "version": 3,
  "slots": [
    {
      "id": "0123456789abcdef",
      "kdf": {"m_cost_kib": 65536, "t_cost": 4, "p_cost": 4},
      "salt": [..32 bytes..],
      "nonce": [..12 bytes..],
      "wrapped_master_key": [..master ‖ GCM tag..]
    }
  ]
}
```

The master key is generated once at `init`. Each slot has a fresh random
salt, a random 96-bit nonce, and AAD `"keres-vault-config-v3/" + slot_id`, so
wrapped keys cannot be transplanted between slots undetected. Unlocking tries
each slot; `change_password` re-wraps only the slot that matched;
`add_keyslot` appends a slot; `remove_keyslot` deletes one and must be
authorized by a passphrase from a slot that remains. Slot ids are plaintext,
like the rest of the bootstrap structure. Wrong password and tampered
config are indistinguishable (`Authentication`) by design; a structurally
malformed slot is `InvalidVault`.

Version 2 configs (the 0.5.x single implicit slot, fixed nonce, AAD
`"keres-vault-config-v2"`) are still read and are rewritten as version 3 the
next time a key operation changes the config. No password changes during that
upgrade.

### vault.recovery (recovery kit)

Optional. Created by `keres recovery create` / `Vault::create_recovery_kit`:
a second, independent wrapping of the same master key.

```json
{
  "version": 1,
  "kdf": {"m_cost_kib": 65536, "t_cost": 4, "p_cost": 4},
  "salt": [..32 bytes..],
  "nonce": [..12 bytes..],
  "wrapped_master_key": [..master ‖ GCM tag..]
}
```

The KEK is Argon2id over a random 160-bit code, printed once as nine groups
of four Crockford Base32 symbols with a 16-bit checksum. The code is never
stored. The file is not a container because it must be parsed before any key
exists; AEAD with a random nonce and AAD `"keres-vault-recovery-v1"`
authenticates it. `Vault::recover` validates the unwrapped master against the
encrypted index, re-wraps `vault.config` as a fresh single-slot config, and
consumes the kit. Losing `vault.config` no longer bricks the vault; losing
the code still does. Any extra keyslots are lost in recovery and must be
re-added.

### vault.rotate (rotation journal)

`Vault::rotate` / `keres rotate` performs an opt-in **deep rotation**: it
generates a fresh master key, streams every blob through re-encryption, and
rewrites the index under the new key. The new config has exactly one keyslot
under the new password; other keyslots and the recovery kit wrapped the old
master key and are discarded.

Rotation writes `d/.manifest.enc.next`, then a small `vault.rotate` journal
containing the new config (already wrapped) and the SHA-256 of the staged
manifest — never a plaintext key:

```json
{"version": 1, "manifest_sha256": "..64 hex..", "config": "{..v3 config..}"}
```

The journal write is the commit point. After it, the staged manifest is
renamed over `.manifest.enc`, the config is replaced, the old recovery kit is
removed, and the journal is deleted. If the process dies after the journal
but before completion, the next operation that opens the vault finishes the
swap: it compares the journal hash against the canonical and staged
manifests, promotes the staged one when it matches, and installs the config.
If neither manifest matches, the rotation is rolled back and the journal is
discarded. Before the journal exists, the old vault is untouched and the
staged blobs are ordinary orphans for `prune_orphans`.

Old blobs are unreachable under the new master; rotation removes them
best-effort after the swap, and any leftovers are reclaimed by
`verify --prune`.

### Blob locations

```
blob_path(entry_id) = d / sha256(master_key ‖ entry_id)[..2] /
                          sha256(...)[2..50] + ".enc"
```

Paths are deterministic (stable across restarts and renames), keyed by the
master key (so unrelated vaults never share blob names), and leak nothing but
entry count and rough sizes via the tree shape. Because the hash input is the
entry's stable ID rather than its path, renaming an entry only updates the
encrypted index; no ciphertext is re-encrypted.

### Index: snapshot + append-only log

The logical index is a `BTreeMap<String, EntryMetadata>` serialized to JSON.
Each `EntryMetadata` records a non-empty 128-bit hex `id`, the original name,
size, directory flag, and child lists for directories.

The index is stored in two parts:

- `d/.manifest.enc` — a compacted snapshot, written as a kind-0 container with
  payload type `Manifest`.
- `d/.index.log` — encrypted, authenticated mutation batches appended after
  that snapshot.

Saving an operation does **not** rewrite the whole snapshot. The library loads
the current logical index (snapshot plus replayed log), computes the set of
`put`/`delete` records that turn it into the new map, and appends them as one
batch. Reading decodes the snapshot once and replays each batch in order.

```
log header:  b"KERESIDX" | version u16 | generation u64 |
             snapshot_sha256[32] | log_id[32]
log record:  len u32 | index u64 | nonce[12] | ciphertext || GCM tag
```

Each log gets a random `log_id`; its record key is
`HKDF(master, log_id, "keres-vault-index-log-v1")`. Record AAD binds the full
header bytes and the record index, so records cannot be moved between logs,
reordered, or replayed under another generation. The header's snapshot hash
ties the log to exactly one snapshot: mixing a log with a different snapshot
is `InvalidVault`, and a log whose key does not authenticate is
`Authentication`.

The snapshot's authenticated JSON also carries a monotonic `generation`
(pre-generation v3 snapshots read as `0`). A log must declare the same
generation as the snapshot it extends; a mismatch is `InvalidVault`.
Compaction writes `generation + 1` into the new snapshot and its empty log.
Generations are internal: they make replace/compaction swaps unambiguous and
support consistent read snapshots, but without hardware-backed state they are
not a rollback detector.

A log is written with one `write_all` plus `sync_data` per batch. A crash may
leave a torn final record; replay stops at the last valid record and the next
append truncates the tail. Damage in the middle of the log is an error, never
a silent truncation.

When the log reaches 512 records or 8 MiB, the next save compacts it: a fresh
snapshot is written, a new empty log is created that names it by SHA-256, and
the old log is removed. Compaction is journaled in `d/.index.compact`; an
interrupted compaction is finished on the next lock acquisition. Deep rotation
and migration install a new snapshot and remove any log encrypted under the
old index key.

Version 2 manifests are rejected by the reader with `MigrationRequired`
(and an empty ID in a version 3 manifest is rejected as `InvalidVault`; IDs
are the root of blob identity, so a missing one cannot be repaired safely).
`Vault::migrate` / `keres migrate` upgrades a v2 vault in place: it
re-encrypts every entry under a fresh ID, then commits the v3 snapshot
atomically. A failure before that commit leaves the legacy manifest intact.

Load semantics (hardened after audit finding #1):

| State | Result |
|---|---|
| Snapshot and log absent | empty index (fresh/uninitialized data dir) |
| Snapshot present but damaged/truncated/unauthentic | **error** — never silently empty |
| Log present but snapshot absent, or bound to another snapshot/generation | **error** |
| Snapshot larger than the 64 MiB read cap | rejected before allocation |

### Operations

| API | Behavior notes |
|---|---|
| `init(pw)` | creates dir mode 0700, config, empty index snapshot |
| `unlock` / `lock` | unwraps master into memory / drops it |
| `add(src, name)` | validates target name, rejects collisions & separators; directories recurse, creating placeholder entries; every blob temp+rename; index batch appended last |
| `replace(src, name)` | rewrites one existing file blob and appends a new index record; directory entries are rejected |
| `rename(from, to)` | top-level only; appends `put` records for the new keys and child lists (for directories, the whole subtree) without touching ciphertext |
| `list()` | reads snapshot + log only — no blobs touched, fast |
| `extract(name, dest)` | recreates hierarchy; names sanitized; outputs via temp+rename |
| `remove(name)` | removes subtree blobs and appends `delete` records (no orphans from successful ops) |
| `change_password(old,new)` | verifies old, re-wraps only that keyslot; ciphertext and other slots untouched |
| `rotate(old,new)` | deep rotation: fresh master key, all blobs re-encrypted, snapshot rewritten and the old log removed; collapses to one keyslot, removes the recovery kit, leaves the vault locked; crash-safe via `vault.rotate` |
| `keyslots()` | lists plaintext slot ids; no password required |
| `add_keyslot(existing,new)` | verifies an existing passphrase and appends an independent slot; upgrades a legacy config |
| `remove_keyslot(id,pw)` | revokes a slot, authorized by a passphrase from a slot that remains; the last slot is refused |
| `verify(pw)` | decrypts every blob (type-checked), cross-checks the replayed index; returns `IntegrityReport{total, verified, missing[], corrupted[]}` |
| `prune_orphans()` | deletes `.enc` blobs and stale `.tmp-*` files under `d/` that no replayed index record references; refuses if the snapshot is missing |
| `migrate(pw)` | one-way v2 → v3 upgrade: re-encrypts every entry under a fresh ID, swaps the snapshot atomically, then removes legacy blobs; returns `MigrationReport{entries, bytes}` |
| `create_recovery_kit(pw)` | verifies the password, writes `vault.recovery`, returns a one-time printable `RecoveryCode` |
| `recover(code,new_pw)` | unwraps the master with the code, validates it against the index, re-wraps the config, consumes the kit |

Directory removal walks the manifest's own child lists, so removing a
directory removes everything beneath it even if nested names were added
out of order.

### Path-traversal defense

Names recovered from trailers/manifests pass `sanitize.rs`: absolute paths,
`..` components, drive letters and NUL bytes are rejected or rewritten
before joining. An encrypted archive cannot plant files outside the
destination.

---

## Crash safety and durability

Invariants: a crash may lose the *current* operation, never corrupt
*previous* state.

- All persistent writes go through: create temp file in same directory →
  restrict to owner-only → write → `sync_all()` → `rename()` over target →
  `sync_dir()` on the parent directory.
- Containers and snapshots are immutable once written; updates replace whole
  files via temp+rename. The index log is the one append-in-place file; it is
  record-framed so a torn final write is detected and truncated. There are no
  torn-header states.
- Failure mid-add leaves unreferenced blobs (index batch not yet appended) —
  visible to nobody, and reclaimed by `verify --prune` /
  `Vault::prune_orphans`.
- Deep rotation commits through `vault.rotate` before touching the canonical
  index, so an interrupted run is either rolled back or completed on the next
  open. A staged `.manifest.enc.next` without a journal is ignored.
- Index compaction commits through `d/.index.compact` before the snapshot/log
  swap. An interrupted run promotes or discards the staged pair on the next
  lock acquisition; staged files without a journal are deleted.

---

## Memory hygiene

- Every key is `Key(Zeroizing<[u8; 32]>)`; derived plaintext buffers that
  contain secrets (master key, manifest JSON, trailer records) use
  `Zeroizing<Vec<u8>>`. Overwritten on drop.
- `Debug` for `Key` prints `Key([REDACTED])`; keys are passed by reference
  and never serialized or logged.
- Chunk buffers are reused; scratch vectors holding secret material are
  zeroizing types.
- Not yet done (by design, `forbid(unsafe_code)`): `mlock`, core-dump
  suppression. Roadmapped behind a tiny audited unsafe boundary.

---

## Error taxonomy

One enum (`Error`, thiserror), `Result<T> = std::result::Result<T, Error>`:

| Variant | Means |
|---|---|
| `Authentication` | wrong password/key **or** any tampering — indistinguishable on purpose |
| `InvalidHeader` | malformed kind, lengths, or trailer |
| `UnsupportedVersion(u32)` | envelope/schema/config version newer than supported |
| `MigrationRequired` | legacy vault manifest; run `keres migrate` |
| `IncompatibleFormat` | file is not a current Keres container |
| `InvalidVault` | vault structure problems (bad config, damaged manifest) |
| `VaultLocked` / `VaultUnlocked` | state-machine misuse |
| `VaultBusy` | another process holds the vault lock |
| `Cancelled` | a streaming operation was stopped by its cancellation flag |
| `EntryExists` / `EntryNotFound` | name conflicts |
| `InvalidName(String)` | validation failure (preview truncated to 32 chars) |
| `Io(std::io::Error)` | filesystem layer |
| `Encryption` / `KeyDerivation` / `InvalidKdfParams` / `MalformedPayload` | internal/crypto-layer failures |

Deliberate policy: callers cannot distinguish "wrong password" from
"corrupted file" — both are `Authentication`. This avoids turning error
messages into a tamper oracle.

---
