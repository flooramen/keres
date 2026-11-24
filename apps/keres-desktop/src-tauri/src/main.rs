use std::path::{Path, PathBuf};

use keres::{
    decrypt_file as decrypt, encrypt_file as encrypt, EntryInfo, Result as KeresResult, Vault,
};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct VaultEntry {
    name: String,
    size: u64,
    is_directory: bool,
}

impl From<EntryInfo> for VaultEntry {
    fn from(entry: EntryInfo) -> Self {
        Self {
            name: entry.name,
            size: entry.size,
            is_directory: entry.is_directory,
        }
    }
}

fn with_unlocked_vault<T>(
    path: PathBuf,
    password: String,
    operation: impl FnOnce(&mut Vault) -> KeresResult<T>,
) -> Result<T, String> {
    let password = Zeroizing::new(password);
    let mut vault = Vault::new(path);
    vault.unlock(&password).map_err(|error| error.to_string())?;
    let result = operation(&mut vault).map_err(|error| error.to_string());
    vault.lock();
    result
}

#[tauri::command]
fn encrypt_file(input: String, output: String, password: String) -> Result<String, String> {
    let password = Zeroizing::new(password);
    encrypt(&password, Path::new(&input), Some(Path::new(&output)))
        .map(|path| path.display().to_string())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn decrypt_file(input: String, output: String, password: String) -> Result<String, String> {
    let password = Zeroizing::new(password);
    decrypt(&password, Path::new(&input), Path::new(&output))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn create_vault(path: String, password: String) -> Result<String, String> {
    let password = Zeroizing::new(password);
    let mut vault = Vault::new(PathBuf::from(&path));
    vault.init(&password).map_err(|error| error.to_string())?;
    vault.lock();
    Ok(format!("Vault created at {path}"))
}

#[tauri::command]
fn list_vault(path: String, password: String) -> Result<Vec<VaultEntry>, String> {
    with_unlocked_vault(PathBuf::from(path), password, |vault| {
        vault
            .list()
            .map(|entries| entries.into_iter().map(VaultEntry::from).collect())
    })
}

#[tauri::command]
fn add_to_vault(
    path: String,
    password: String,
    source: String,
    name: Option<String>,
) -> Result<String, String> {
    with_unlocked_vault(PathBuf::from(path), password, |vault| {
        vault.add(Path::new(&source), name.as_deref())?;
        Ok("Entry added to vault".to_owned())
    })
}

#[tauri::command]
fn extract_from_vault(
    path: String,
    password: String,
    name: String,
    destination: String,
) -> Result<String, String> {
    with_unlocked_vault(PathBuf::from(path), password, |vault| {
        vault
            .extract(&name, Path::new(&destination))
            .map(|output| format!("Extracted to {}", output.display()))
    })
}

#[tauri::command]
fn remove_from_vault(path: String, password: String, name: String) -> Result<String, String> {
    with_unlocked_vault(PathBuf::from(path), password, |vault| {
        vault.remove(&name)?;
        Ok(format!("Removed {name}"))
    })
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            encrypt_file,
            decrypt_file,
            create_vault,
            list_vault,
            add_to_vault,
            extract_from_vault,
            remove_from_vault
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Keres Desktop");
}
