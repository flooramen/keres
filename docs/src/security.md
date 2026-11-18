# Threat Model

Keres protects **data at rest** against an adversary with read access to the
storage medium: stolen laptops, leaked cloud backups, seized disks. The
adversary may also attempt to modify stored ciphertext.

Out of scope: malware on the user's machine while a vault is unlocked,
keyloggers, compromised OS, side channels on the CPU (e.g. Rowhammer),
and coercion of the password itself.

## Cryptographic Design

    | Primitive | Role |
    |---|---|
    | AES-256-GCM | AEAD for all ciphertext (chunks, trailers, manifests, index-log records, wrapped keys) |
    | Argon2id (64 MiB, t=4, p=4) | Password → KEK; parameters serialized per container |
    | HKDF-SHA256 | Master key → per-object subkeys; manifest and index-log key derivation |
    | SHA-256 | Blob path derivation (`SHA256(master ‖ path)`), verification hash |

### Nonces

- **Single-file / vault entries:** 12-byte nonce = `0x0000_0000 ‖ chunk_index (u64 BE)`
  under an HKDF subkey unique to the object and its salt. Counter nonces are
  collision-free within an object regardless of size or restarts.
- **Trailer:** reserved all-`0xFF` nonce, distinct domain from data chunks.
- **Manifest snapshot:** container chunk nonces under an HKDF subkey with a
  fresh random `object_salt` on every save.
- **Config / recovery wrap:** a fresh random 96-bit nonce for every wrapping
  operation, under a KEK derived from that slot's own random salt.
- **Index log:** a fresh random 96-bit nonce per record under an HKDF subkey
  derived from the master and a random per-log `log_id`. The AAD binds the
  authenticated log header and the record index, so records cannot be
  reordered, spliced between logs, or replayed under another generation.

### Associated Data

Every AEAD operation binds the container's payload-type context
(`"keres-container-v1/file"`, …) plus the chunk index, and the trailer
additionally binds a `/trailer` suffix. Consequences:

- Reordering chunks between positions → authentication failure.
- Truncating the file → detected by trailer cross-check of `size`/`chunk_count`.
- Moving bytes between two `.krs` files (same password!) → fails because each
  container derives an independent object salt/subkey.
- The unauthenticated end-of-chunks marker cannot be exploited: the trailer is
  authenticated and its `chunk_count` must match exactly what preceded it.

### Key Hierarchy

```
password ─Argon2id─► KEK ─wrap─► master key (vault.config)
                                    ├─► HKDF subkeys per entry blob
                                    ├─► HKDF manifest snapshot key
                                    └─► HKDF index-log key (per log_id)
```

`change_password` re-wraps only the matching keyslot; no re-encryption of data.
`rotate` generates a new master key and re-encrypts the current entries, but no
rotation can invalidate ciphertext copies an attacker has already
exfiltrated.

## Memory Handling

- All keys are held in `Zeroizing<[u8; 32]>`; buffers are zeroized on drop.
- Keys are never copied by value into logs, errors, or serialization.
- The crate is compiled with `#![forbid(unsafe_code)]`; we do not use mlock
  or core-dump suppression (see Limitations).

## Filesystem Hardening

- Atomic writes: temp file in the same directory + `fsync` + `rename`, so a
  crash mid-write can never corrupt a vault config, snapshot, or journal.
- The index log is the only append-in-place file. It is record-framed and
  each batch is written with one `write_all` + `sync_data`; a torn final
  record is detected and truncated on the next write, while damage earlier in
  the log is reported as an authentication failure.
- Temp files are opened with `O_CREAT | O_EXCL`, so a path that already
  exists — including a planted symlink — makes the operation fail rather
  than being written through. On Unix they are mode `0600` from creation.
- Vault directories and `.krs` outputs are created with mode `0700`/`0600`
  on Unix.
- Names read back from containers are sanitized before path joins;
  absolute paths, `..`, separators and control characters are rejected —
  a malicious vault archive cannot write outside its directory.
- Directory removal walks the encrypted manifest's child lists, so removing
  a tree leaves no orphaned blobs.
- Vault access is serialized with an advisory lock on `vault.lock`: writers
  take it exclusively, readers share it, and a contended operation returns
  `Error::VaultBusy`. The lock is not a security boundary against a process
  that deliberately ignores it.

## Format Versioning Policy

Since 0.4, all objects use one universal container: an 8-byte magic
(`KERES\0\0\0`, with a control byte so it can never occur in plain text),
a u16 envelope version, a key-derivation kind byte (HKDF-from-master for
vault objects, Argon2id password for standalone files), chunk records and
an authenticated trailer carrying the payload type (`file`, `directory`,
`manifest`).

Rules that keep this stable:

1. Every container writes the `KERES\0\0\0` magic. Envelope revisions bump
   the version field; readers reject unknown versions with
   `UnsupportedVersion`.
2. A released payload type never changes meaning; new object kinds are
   new trailer types with new context strings.
3. Only the current Keres format is accepted. Any other magic returns
   `Error::IncompatibleFormat`; extract old data with the release that wrote
   it before upgrading. Vault manifests are the exception: a 0.5.x (manifest
   v2) vault returns `MigrationRequired` and is upgraded in place by
   `keres migrate` / `Vault::migrate`.
4. Vault directories are forward-only. Since 0.7 a vault may contain an
   append-only `d/.index.log`; pre-0.7 releases do not know about it and can
   silently show or write a stale index. Do not alternate releases on the
   same vault directory.

## Verification API

`Vault::verify()` authenticates every blob and the replayed index (snapshot
plus log), reporting a per-entry integrity report without writing plaintext to
disk.

## Recovery Kit

`Vault::create_recovery_kit()` writes a second wrapping of the master key to
`vault.recovery`, protected by a random 160-bit code printed once as Crockford
Base32 with a 16-bit checksum. Neither the code nor the master key is stored in
plaintext. `Vault::recover()` can recreate a lost or corrupt `vault.config`
after validating the recovered key against the encrypted index, then consumes
the kit so the code cannot be replayed.

For an attacker who steals the vault directory, the recovery file is a second
offline guessing target; 160 bits plus Argon2id makes exhaustive search
infeasible. The code must still be stored separately and handled like the
vault itself. Creating a new kit replaces the old wrapping; losing both the
code and the password remains unrecoverable.

## Keyslots

`vault.config` version 3 stores independent keyslots, each wrapping the same
master key under its own Argon2id-derived KEK. Passphrases are never stored or
compared to each other; unlocking derives a KEK per slot and succeeds when one
AEAD tag verifies. Changing a password re-wraps one slot. Adding a slot does
not alter ciphertext. Removing a slot drops that wrapping and revokes the
passphrase.

Revocation is not key rotation: the master key stays the same. An attacker who
had already used the revoked passphrase to unwrap the master key keeps access
to the ciphertext until the vault is deeply rotated or rebuilt. Revoking a
keyslot is therefore a control for lost devices and role changes, not a
remedy for a key that may have leaked. For that case, `Vault::rotate` /
`keres rotate` re-encrypts every entry under a fresh master key; it is
deliberately slow, collapses the vault to one keyslot under the new password,
and removes any recovery kit.

Malformed slots fail closed with `InvalidVault`; a wrong passphrase across all
slots is indistinguishable from a tampered wrapping (`Authentication`). Slot
ids and the slot count are plaintext metadata in `vault.config`.

## Known Limitations

1. **No memory locking** — with `forbid(unsafe_code)` we cannot call
   `mlock`; unlocked keys may hit swap if the system has no encrypted swap.
2. **No automatic key rotation of content** — changing the password re-wraps
   the master key but old ciphertext snapshots remain decryptable with the
   old password forever. Deep rotation (`Vault::rotate`) re-encrypts the
   current vault under a fresh master key, but cannot reach snapshots an
   attacker already copied.
3. **No deniability** — format magics and structure identify files as
   Keres containers.
4. **Single-factor** — no hardware-token or multi-party key splitting.
5. **Filename leakage via size** — plaintext lengths are visible through
   ciphertext length (chunked at 64 KiB granularity).
6. **Trust on first unlock** — the config stores a verification hash rather
   than a signature; there is no protection against full-storage rollback to
   an older valid vault snapshot. Truncating the tail of the index log is
   likewise indistinguishable from an interrupted append.
7. **Operation-pattern leakage** — the index log's record count, size, and
   approximate write order reveal how many mutations happened and roughly
   when. Entry sizes are not padded to buckets yet; access patterns are not
   hidden.

## Reporting

Please report vulnerabilities privately to the maintainers instead opening a
public issue.

