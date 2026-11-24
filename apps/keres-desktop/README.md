# Keres Desktop

A Tauri desktop client for Keres. It uses the `keres` Rust library directly
for single-file encryption/decryption and basic vault management; it does not
shell out to the CLI.

## Install on Windows

Once a Windows desktop release has been published:

1. Open the [Keres GitHub Releases](https://github.com/Keres-rs/keres/releases)
   page and choose the latest release whose name starts with `desktop-v`.
2. Download either the `.exe` setup installer (recommended) or the `.msi`
   installer.
3. Run the downloaded installer and follow its prompts. After installation,
   launch **Keres Desktop** from the Windows Start menu.

The installer includes the WebView2 runtime, so end users do not need to
install Rust, Node.js, WebView2 separately, or have an internet connection
during installation. Windows may show a SmartScreen warning because the
installers are not code-signed yet; only install a copy downloaded from the
official Keres release page.

## Build from source

### Requirements

- Rust/Cargo 1.85 or newer
- Node.js and npm
- For Windows builds: Visual Studio C++ Build Tools
- Tauri v2's platform prerequisites, including the system WebView libraries
  for Linux: <https://v2.tauri.app/start/prerequisites/>

### Run in development

From this directory:

```console
npm ci
npm run tauri dev
```

On Windows, create both an NSIS setup executable and an MSI installer with:

```console
npm run build:windows
```

The installers are written to `src-tauri/target/release/bundle/nsis/` and
`src-tauri/target/release/bundle/msi/`. A Windows installer build is also
available from the repository's **Desktop Windows Installer** GitHub Actions
workflow; tagged releases (`desktop-v<version>`) publish both installers.
The MSI target must be built on Windows; the workflow uses a Windows runner
for both installer formats.
Windows installers embed Microsoft's offline WebView2 installer (about 127 MB
extra), so users do not need Rust, Node.js, an internet connection, or a
separate WebView2 installation to install and run Keres Desktop. Rust, Node.js,
and Visual Studio Build Tools are required only on the machine building the
installer.
Unsigned builds may display a Microsoft Defender SmartScreen warning; trusted
public distribution requires signing the installers with a code-signing
certificate.

The app asks for file and vault paths through native dialogs. Passwords are
sent to Rust only for the operation in progress and are not saved by the app.
Avoid screenshots or screen sharing that expose paths or vault entry names.

## Current scope

- Encrypt and decrypt one file at a time.
- Create vaults, list their top-level entries, add files/folders, extract
  entries, and remove entries.

For integrity verification, recovery, keyslots, migration, and other advanced
operations, use the CLI or Rust library.
