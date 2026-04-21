use serde_json::json;
use semver::Version;
use tauri_plugin_store::StoreExt;

pub struct VersionControl {
    pub version: Version,
}

impl VersionControl {
    pub fn version() -> Version {
        return Version::new(0, 1, 0)
    }
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

/// API
pub mod api;
pub mod oint_components;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet])
        .invoke_handler(tauri::generate_handler![api::generate_with_algorithm])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
