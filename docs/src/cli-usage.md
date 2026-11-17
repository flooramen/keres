# Keres CLI usage

Run `keres help` or `keres <command> --help` for the built-in reference.

## Single files

```console
# Encrypt to a random-looking `.krs` name.
$ keres encrypt document.pdf

# Encrypt to an explicit path.
$ keres encrypt document.pdf backup.krs

# Decrypt; the original filename is recovered from the container.
$ keres decrypt backup.krs restored.pdf
```

## Vaults

Vaults are named and stored under `~/.keres/vaults/<name>` by default.

```console
$ keres init personal
$ keres add personal ./notes.txt
$ keres add personal ./photos --name photos
$ keres replace personal ./notes-v2.txt notes.txt
$ keres rename personal notes.txt journal.txt
$ keres list personal
$ keres extract personal photos ./restored
$ keres verify personal
$ keres verify personal --prune
$ keres migrate legacy-vault
$ keres recovery create personal
$ keres recovery use personal
$ keres change-password personal
$ keres remove personal notes.txt
```

### Commands

| Command | Description |
|---|---|
| `init <vault>` | Create a new vault |
| `add <vault> <path> [--name NAME]` | Add a file or directory tree |
| `replace <vault> <path> <name>` | Replace an existing file entry |
| `rename <vault> <from> <to>` | Rename a top-level file or directory |
| `remove <vault> <name> [--force]` | Remove an entry and, for directories, its subtree |
| `list <vault>` | List top-level entries |
| `extract <vault> <name> <dest> [--force]` | Restore an entry |
| `verify <vault> [--prune]` | Authenticate every entry; `--prune` deletes unreferenced blobs |
| `migrate <vault> [--force]` | Upgrade a 0.5.x (manifest v2) vault to the current format |
| `recovery create <vault> [--force]` | Create or replace the printable recovery kit |
| `recovery use <vault>` | Reset the password with a recovery code (consumes the kit) |
| `change-password <vault>` | Re-wrap the master key under a new password |
| `encrypt <input> [output] [--force]` | Encrypt one file |
| `decrypt <input> <output> [--force]` | Decrypt one file |

## Overwriting and destructive operations

`remove` and `migrate` ask for confirmation on a terminal and refuse to run
without `--force` when standard input is not a terminal. `extract`,
`encrypt`, and `decrypt` refuse to overwrite an existing destination unless
`--force` is given.

`migrate` upgrades a vault written by 0.5.x (manifest v2). It re-encrypts
every entry in place, keeps the same password, commits the v3 manifest
atomically, and then deletes the legacy blobs. Back up the vault directory
first; the upgrade is one-way.

`recovery create` prints a one-time code and writes `vault.recovery`, a
second wrapping of the master key. Store the printed code offline and
separately from the vault: either the vault directory or the code alone is
not enough. `recovery use` prompts for the code, verifies it against the
encrypted index, sets a new password, and deletes the kit so the code cannot
be replayed. `recovery create --force` replaces an existing kit and
invalidates its old code.

`verify --prune` deletes ciphertext blobs under `d/` that no manifest entry
references (left behind by an interrupted add) and cleans up stale temp
files. It only prunes after a successful integrity check and refuses to run
if the manifest is missing.

## Passwords in scripts

`keres` prompts on a terminal. For scripts and CI, choose one of:

```console
# Read the first line of a file (kept out of the environment).
$ keres --password-file /run/secrets/keres init personal

# Read from standard input.
$ printf '%s\n' "$SECRET" | keres --password-stdin list personal

# Environment variable (convenient, but visible to the same user in /proc).
$ KERES_PASSWORD="$SECRET" keres add personal ./report.pdf
```

Explicit flags take priority over `KERES_PASSWORD`, which takes priority over
an interactive prompt. Password values are held in zeroizing buffers and
scrubbed when the command finishes. Prefer a terminal prompt or a
permission-restricted password file on shared machines.

`change-password` reads one password per prompt, so with
`--password-stdin` it expects the current password, the new password, and the
confirmation on three consecutive lines. With `--password-file` or
`KERES_PASSWORD` every prompt gets the same value, which is rejected because
the new password must differ from the current one.
