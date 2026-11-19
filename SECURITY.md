# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers through
GitHub's [private vulnerability reporting](https://github.com/Keres-rs/keres/security/advisories/new)
or by opening a draft security advisory. Do not open a public issue for a
vulnerability. Include:

- affected version(s) and platform,
- a minimal reproducer or proof of concept,
- the security property you believe is broken.

We aim to acknowledge reports within 72 hours and will coordinate disclosure.
Please give us a reasonable window to ship a fix before publishing details.

## What Keres protects against

Keres protects data at rest against an attacker with read access to the
storage medium (stolen disk, leaked backup, synced cloud folder) and against
an attacker with write access who modifies, truncates, reorders, or
transplants ciphertext. Authenticated encryption covers every chunk and the
trailer; vault object locations are keyed by the master key.

## What it does not protect against

- Malware, keyloggers, or a compromised OS while a vault is unlocked.
- An attacker who knows the password or has the unlocked process memory.
- Coercion to reveal the password.
- Traffic analysis of *sizes*: entry counts, directory shape, and exact file
  sizes leak unless opt-in size padding is enabled. Even with padding, access
  patterns and timing remain observable.
- Rollback to an older valid snapshot of the whole vault directory. The index
  carries an internal generation and each entry records a plaintext content
  hash, so a substituted blob for the same entry is detected; neither is a
  hardware-backed anti-rollback counter.
- Retroactive crypto-erasure. `Vault::erase` rotates the master key so the old
  key stops working against the vault, but a copy of the deleted blob plus an
  old key/config captured beforehand stays decryptable.
- Secure erasure of deleted ciphertext on SSDs or journaling filesystems.

The full threat model and design rationale are in
[`docs/src/security.md`](docs/src/security.md).

## Scope

The security surface is the code in `crates/keres` and
`crates/keres-cli`. The GUI and Python bindings are separate projects and
have their own reporting processes.

## Supported versions

Keres is pre-1.0. Security fixes are applied to the latest published release
(currently the 0.7.x line). Only the current Keres container format is
supported. Every other format, including pre-rename Krypton containers and
pre-0.4 formats, returns `Error::IncompatibleFormat`. A 0.5.x vault
(manifest v2) returns `Error::MigrationRequired` and is upgraded with
`keres migrate`.
