# Keres library usage

## Single file

```rust
use keres::{decrypt_file, encrypt_file};
use std::path::Path;

// Encrypt. `None` writes a random-looking `.krs` name in the current dir.
let out = encrypt_file("correct horse", Path::new("document.pdf"), None)?;

// Decrypt. Returns the original filename recovered from the authenticated
// trailer; treat it as untrusted if you use it to build paths.
let original_name = decrypt_file("correct horse", &out, Path::new("restored.pdf"))?;
assert_eq!(original_name, "document.pdf");
# Ok::<(), keres::Error>(())
```

The container is self-contained: it carries the Argon2id parameters and the
encrypted original filename.

## Vault

```rust
use keres::Vault;
use std::path::Path;

let mut vault = Vault::new("myvault".into());

// First run: create the vault. `init` fails if it already exists.
if !vault.exists() {
    vault.init("correct horse battery staple")?;
}
vault.unlock("correct horse battery staple")?;

// Store a file and a whole directory tree.
vault.add(Path::new("report.pdf"), None)?;
vault.add(Path::new("photos"), Some("pictures"))?;

// Replace an existing file entry without removing it first.
vault.replace(Path::new("report-v2.pdf"), "report.pdf")?;

// Rename a top-level entry; ciphertext is not rewritten.
vault.rename("report.pdf", "report-final.pdf")?;

for entry in vault.list()? {
    println!("{} — {} bytes, dir: {}", entry.name, entry.size, entry.is_directory);
}

// Restore. Files are written to `dest`; directories are recreated under it.
vault.extract("report.pdf", Path::new("./out"))?;

// Rotate the password without re-encrypting stored data.
vault.change_password("correct horse battery staple", "new secret")?;

vault.lock();
# Ok::<(), keres::Error>(())
```

## Integrity check

```rust
# use keres::Vault;
let mut vault = Vault::new("myvault".into());
let report = vault.verify("correct horse battery staple")?;
println!("{} of {} entries authenticated", report.verified, report.total_entries);
# Ok::<(), keres::Error>(())
```

`verify` authenticates every blob, checks the plaintext size and SHA-256
content hash recorded in the index, and reports missing or corrupted entries.
It does not write plaintext to disk. The hash check detects a substituted
older blob under the same entry ID; it is not a defense against rollback of
the whole vault directory.

Interrupted adds can leave ciphertext blobs that no manifest record
references. `prune_orphans` removes them (and refuses to run if the manifest
is missing, so it can never mistake a damaged vault for an empty one):

```rust
let removed = vault.prune_orphans()?;
println!("removed {removed} orphaned blobs");
```

## Batch and conditional writes

`add_if` / `replace_if` take an `IndexVersion` captured with `version()` and
return `WriteOutcome::Conflict { .. }` when the vault changed first, leaving it
untouched. `apply_batch` commits several adds, replaces, and removals with one
index write; if any operation fails, the index is unchanged and freshly
written blobs are orphans for `prune_orphans`.

```rust
use keres::{BatchOp, Vault, WriteOutcome};
use std::path::Path;

let mut vault = Vault::new("myvault".into());
vault.unlock("correct horse")?;
let version = vault.version()?;

match vault.add_if(Path::new("new.txt"), None, Some(version))? {
    WriteOutcome::Applied { .. } => println!("added"),
    WriteOutcome::Conflict { current } => println!("changed: {current:?}"),
}

vault.apply_batch(&[
    BatchOp::Replace {
        source: "report-v2.pdf".into(),
        name: "report.pdf".into(),
    },
    BatchOp::Remove {
        name: "old-notes.txt".into(),
    },
])?;
# Ok::<(), keres::Error>(())
```

## Erase and rotation

`change_password` re-wraps the master key without re-encrypting data. To change
the data key itself, use `rotate` (re-encrypt everything, collapse to one
keyslot, drop the recovery kit) or `erase` (omit one entry and rotate in a
single journaled commit):

```rust
# use keres::Vault;
let mut vault = Vault::new("myvault".into());
let report = vault.erase("old-secret.txt", "new password")?;
println!("erased; re-encrypted {} entries", report.entries);
# Ok::<(), keres::Error>(())
```

Both leave the vault locked. Erasure is forward-looking: it invalidates the old
master key against the vault, but cannot revoke a copy of the deleted blob that
an attacker already captured with the old key material.

## Size padding

By default the ciphertext length tracks the plaintext length. Opt-in padding
rounds files up to a bucket before encryption:

```rust
use keres::{Padding, Vault};

let mut vault = Vault::new("private".into());
vault.init_with_padding("correct horse", Padding::Adaptive)?;
# Ok::<(), keres::Error>(())
```

`Padding::Adaptive` uses powers of two clamped to `[4 KiB, 16 MiB]`; larger
payloads round to the next 16 MiB multiple. `Padding::fixed(65536)?` selects a
fixed bucket. The policy is stored in the authenticated index and can be
changed with `set_padding`. Padding hides exact sizes, not access patterns;
manifests and directory placeholders are never padded. For `.krs` files use
`encrypt_file_with_padding`.

## Keyslots and recovery

`keyslots`, `add_keyslot`, and `remove_keyslot` manage independent passphrase
wrappings of the same master key. `create_recovery_kit` writes a second
wrapping protected by a one-time printable code, and `recover` resets the
password if `vault.config` is lost or damaged. Both are demonstrated in the
[CLI guide](cli-usage.md); the library methods map one-to-one.

## Streaming

`keres::streaming` exposes `EncryptWriter` / `DecryptReader` `io` adapters and
`encrypt_stream` / `decrypt_stream`. `StreamOptions` supports a progress
callback and an `AtomicBool` cancellation flag; cancelled operations return
`Error::Cancelled`. Streamed containers interoperate with `encrypt_file` /
`decrypt_file`.

## Building blocks

The `keres::crypto` module exposes `Key`, `seal`/`open` (AEAD with AAD),
`derive_key` (Argon2id), `secure_compare`, and the nonce helpers. Most
applications should use the higher-level APIs above.

## Error handling

All fallible operations return `keres::Result<T>`. Wrong passwords and
tampered ciphertext deliberately map to the same `Error::Authentication`
variant, so callers cannot turn error messages into a tamper oracle.

```rust
use keres::{decrypt_file, Error};
use std::path::Path;

match decrypt_file("pw", Path::new("backup.krs"), Path::new("out.bin")) {
    Ok(original_name) => println!("restored {original_name}"),
    Err(Error::Authentication) => eprintln!("wrong password or corrupted data"),
    Err(e) => eprintln!("failed: {e}"),
}
```
