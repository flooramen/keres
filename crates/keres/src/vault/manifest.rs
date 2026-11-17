//! Vault manifest: the encrypted index of every entry in the vault.
//!
//! The manifest maps each entry's full vault-relative path to its metadata,
//! including the child lists that make recursive removal possible.
//!
//! Stored at `d/.manifest.enc` as a universal keres container (see
//! [`crate::container`]) with HKDF-from-master key derivation and payload
//! type `manifest`; the index JSON is carried in the chunk section, so
//! manifests grow past any artificial size limit.

use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::container::{self, KeyDerivation, PayloadType};
use crate::crypto::{self, Key};
use crate::error::{Error, Result};

/// Upper bound on accepted manifest plaintext, guarding against hostile
/// on-disk files forcing huge allocations (a real vault would need tens of
/// millions of entries to reach this).
const MAX_MANIFEST_LEN: u64 = 64 * 1024 * 1024;

/// Current manifest schema version (inside the authenticated payload).
pub(crate) const MANIFEST_VERSION: u32 = 3;

/// Metadata for one vault entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Stable random identifier. Blob location and container AAD are derived
    /// from it, so entries can be renamed without re-encrypting.
    #[serde(default)]
    pub id: String,
    /// Original filesystem name of the entry.
    #[serde(default)]
    pub original_name: String,
    /// Original size in bytes.
    #[serde(default)]
    pub original_size: u64,
    /// Whether this entry is a directory placeholder.
    #[serde(default)]
    pub is_directory: bool,
    /// Full paths of direct children (directories only).
    #[serde(default)]
    pub children: Option<Vec<String>>,
}

/// The full vault index.
pub(crate) type ManifestMap = BTreeMap<String, EntryMetadata>;

#[derive(Serialize, Deserialize)]
struct ManifestFile {
    version: u32,
    files: ManifestMap,
}

fn manifest_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("d").join(".manifest.enc")
}

/// A decoded manifest, tagged by its on-disk schema version.
pub(crate) enum ManifestContents {
    /// Legacy 0.4/0.5 index: blobs are addressed by entry path and entries
    /// carry no stable ID.
    V2(ManifestMap),
    /// Current index: every entry carries a stable random ID.
    V3(ManifestMap),
}

/// Loads the manifest, fully authenticating its container.
///
/// A *missing* manifest yields an empty index; anything present but damaged,
/// truncated or unauthentic is an error — silently treating corruption as
/// "no entries" would let the next save drop every existing record.
pub(crate) fn load(vault_dir: &Path, master: &Key) -> Result<ManifestMap> {
    let path = manifest_path(vault_dir);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ManifestMap::new()),
        Err(e) => return Err(e.into()),
    };

    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_LEN)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidVault)?;

    decode(&bytes, master)
}

/// Decodes and authenticates manifest bytes. Shared by [`load`] and the
/// hidden fuzz entry point.
pub(crate) fn decode(bytes: &[u8], master: &Key) -> Result<ManifestMap> {
    match decode_contents(bytes, master)? {
        ManifestContents::V2(_) => Err(Error::MigrationRequired),
        ManifestContents::V3(files) => Ok(files),
    }
}

/// Loads a legacy manifest for the one-way upgrade path.
///
/// Unlike [`load`], a missing manifest is an error: migration must never
/// mistake an empty data directory for a complete legacy index.
pub(crate) fn load_legacy_v2(vault_dir: &Path, master: &Key) -> Result<ManifestMap> {
    let path = manifest_path(vault_dir);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::InvalidVault),
        Err(e) => return Err(e.into()),
    };

    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_LEN)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidVault)?;

    match decode_contents(&bytes, master)? {
        ManifestContents::V2(files) => Ok(files),
        ManifestContents::V3(_) => Err(Error::Operation(
            "vault already uses the current format".into(),
        )),
    }
}

/// Decodes the authenticated JSON without enforcing a particular version.
fn decode_contents(bytes: &[u8], master: &Key) -> Result<ManifestContents> {
    if bytes.len() as u64 > MAX_MANIFEST_LEN {
        return Err(Error::InvalidVault);
    }

    let mut json = Zeroizing::new(Vec::new());
    container::read_container(
        Cursor::new(bytes),
        None,
        Some(master),
        PayloadType::Manifest,
        b"vault-manifest",
        |c| {
            json.extend_from_slice(c);
            Ok(())
        },
    )?;

    let manifest: ManifestFile =
        serde_json::from_slice(json.as_slice()).map_err(|_| Error::MalformedPayload)?;
    match manifest.version {
        // Legacy entries deserialize with an empty `id`; migration allocates
        // fresh IDs rather than trusting anything on disk.
        2 => Ok(ManifestContents::V2(manifest.files)),
        MANIFEST_VERSION => {
            if manifest.files.values().any(|entry| entry.id.is_empty()) {
                return Err(Error::InvalidVault);
            }
            Ok(ManifestContents::V3(manifest.files))
        }
        other => Err(Error::UnsupportedVersion(other)),
    }
}

/// Atomically saves the manifest as a fresh container (new object salt on
/// every write).
pub(crate) fn save(vault_dir: &Path, files: &ManifestMap, master: &Key) -> Result<()> {
    let manifest = ManifestFile {
        version: MANIFEST_VERSION,
        files: files.clone(),
    };
    let json = Zeroizing::new(serde_json::to_vec(&manifest).map_err(|_| Error::Encryption)?);

    let mut object_salt = [0u8; container::SALT_LEN];
    crypto::fill_random(&mut object_salt);
    let kd = KeyDerivation::Hkdf { object_salt };

    let mut blob = Vec::new();
    let mut src = Cursor::new(json.as_slice());
    container::write_container(
        &mut blob,
        &kd,
        None,
        Some(master),
        PayloadType::Manifest,
        b"vault-manifest",
        Some(&mut src),
        None,
    )?;

    crate::fsutil::atomic_write(&manifest_path(vault_dir), &blob)
}
