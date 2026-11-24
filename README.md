# Keres

Local-first, metadata-hardened encryption for files, vaults, and developer
secrets. One Rust workspace: engine, CLI, and documentation.

[Documentation](docs/src/intro.md) · [Security](SECURITY.md) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md)

## What is in this repository?

| Path | What it is |
|---|---|
| [`crates/keres`](crates/keres) | The library: `.krs` single-file containers and multi-file encrypted vaults |
| [`crates/keres-cli`](crates/keres-cli) | The `keres` command-line interface |
| [`apps/keres-desktop`](apps/keres-desktop) | The Tauri desktop application |
| [`docs`](docs) | The mdBook documentation site |

Python bindings live in a separate repository.

## Windows desktop app

Download and install the latest desktop build:

- [Windows setup (.exe)](https://github.com/flooramen/keres/releases/download/desktop-v0.1.0/Keres.Desktop_0.1.0_x64-setup.exe) (recommended)
- [Windows installer (.msi)](https://github.com/flooramen/keres/releases/download/desktop-v0.1.0/Keres.Desktop_0.1.0_x64_en-US.msi)

The installer includes the WebView2 runtime; end users do not need Rust,
Node.js, or a separate runtime installation. Windows may show a SmartScreen
warning because this build is unsigned.

## Quick start (CLI)

```console
$ cargo install --path crates/keres-cli

# Single file: the original filename is encrypted inside the container.
$ keres encrypt document.pdf
$ keres decrypt <output>.krs restored.pdf

# Multi-file vault.
$ keres init personal
$ keres add personal ./photos --name photos
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
```

Run `keres help` for the full command list.

## Quick start (library)

```toml
[dependencies]
keres = "0.7"
```

```rust
use keres::{decrypt_file, encrypt_file, Vault};
use std::path::Path;

// One file in, one file out.
let out = encrypt_file("correct horse", Path::new("document.pdf"), None)?;
let original_name = decrypt_file("correct horse", &out, Path::new("restored.pdf"))?;
assert_eq!(original_name, "document.pdf");

// A vault for many files.
let mut vault = Vault::new("myvault".into());
vault.init("correct horse")?;
vault.add(Path::new("secret.pdf"), None)?;
vault.extract("secret.pdf", Path::new("./out"))?;
vault.lock();
```

The public API lives in `keres::*` (`encrypt_file`, `decrypt_file`,
`encrypt_stream`, `decrypt_stream`, `Vault`, `EntryInfo`, `IntegrityReport`,
`KeyslotInfo`, `MigrationReport`, `RecoveryCode`, `RotationReport`), with
lower-level building blocks in `keres::crypto`, `keres::kdf`,
`keres::sanitize`, and `keres::error`. `keres::streaming` also exposes
`EncryptWriter` / `DecryptReader` `io` adapters with progress and
cancellation. Run `cargo doc -p keres --open` for the full API reference.

## Design in one paragraph

Every object — a `.krs` file, a vault entry, or the vault index — uses one
authenticated container format: an 8-byte `KERES\0\0\0` magic, a versioned
header whose fields are checked or participate in key derivation, 64 KiB
AES-256-GCM chunks
with counter nonces and AAD binding, and an authenticated trailer. Passwords
go through Argon2id to a key-encryption key; vaults wrap a random master key
once and derive an independent HKDF subkey per object, so changing the
password never re-encrypts stored data. See
[docs/src/architecture.md](docs/src/architecture.md) for the full design.

## Development

```console
$ cargo test --workspace --all-targets
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --all -- --check
$ cargo doc --workspace --no-deps
$ mdbook serve docs
```

The desktop app has its own frontend toolchain; see
[`apps/keres-desktop/README.md`](apps/keres-desktop/README.md) to run it.

The CI matrix runs the workspace tests on Linux, Windows, and macOS, plus
the MSRV (1.85) on Linux. It also checks formatting, clippy, rustdoc, and
package dry-runs, and builds the documentation book.

## Status

Keres is pre-1.0. The container format is versioned and documented, but the
public API may change. The project has not yet had an independent security
audit. See [SECURITY.md](SECURITY.md) for the threat model, guarantees, and
known limitations. Names and directory structure are always encrypted, but
entry counts and exact file sizes remain observable by default. Opt-in size
padding (`--padding` / `Padding`) hides exact sizes behind buckets; it does
not hide access patterns, so Keres does not claim full metadata protection.

## License

Code is licensed under [Apache-2.0](LICENSE). The documentation in `docs/` is
licensed under CC0-1.0; see [`docs/LICENSE`](docs/LICENSE).
