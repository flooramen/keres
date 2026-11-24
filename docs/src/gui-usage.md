# Keres desktop app

Keres includes a Tauri desktop application in
[`apps/keres-desktop`](../../apps/keres-desktop). It calls the Rust `keres`
library directly and currently provides single-file encryption/decryption and
basic vault management.

Follow the app's README for prerequisites and development instructions. The
CLI and library remain available for terminal and programmatic workflows.
For Windows, the app can be packaged as an NSIS setup executable and an MSI
installer; see the app README for local builds and published releases.

The app is an early desktop client; the library's documented security model
and limitations apply to it as well.
