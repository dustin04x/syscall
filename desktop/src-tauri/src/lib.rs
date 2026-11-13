//! Read-only Tauri backend for the SYSCALL forensic workbench.
//!
//! The frontend can only call typed commands. Database paths are fixed at
//! process startup, all SQL lives in `syscall-storage`, and analysis,
//! verification, and export are delegated to their existing Rust crates.

#[cfg(feature = "desktop-app")]
mod commands;
mod contract;
mod error;
mod service;

use std::path::PathBuf;
#[cfg(feature = "desktop-app")]
use std::sync::Arc;

use syscall_core::paths::{default_data_dir, default_db_path};
#[cfg(feature = "desktop-app")]
use tauri::Manager;

#[cfg(feature = "desktop-app")]
use commands::AppState;
pub use contract::*;
pub use error::{CommandError, DesktopError};
pub use service::DesktopService;

#[cfg(feature = "desktop-app")]
pub fn run() {
    let database_path = resolve_database_path();
    let export_directory = resolve_export_directory();
    let service = Arc::new(DesktopService::new(database_path, export_directory));

    tauri::Builder::default()
        .manage(AppState { service })
        .setup(|app| {
            let window = app
                .get_webview_window("main")
                .ok_or("main webview window was not created")?;
            window
                .set_title("SYSCALL Workbench")
                .map_err(|err| format!("could not set window title: {err}"))?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::list_sessions,
            commands::get_overview,
            commands::get_session,
            commands::list_processes,
            commands::query_timeline,
            commands::query_filesystem,
            commands::query_network,
            commands::get_event,
            commands::run_analysis,
            commands::run_verification,
            commands::export_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SYSCALL Workbench");
}

#[cfg_attr(not(feature = "desktop-app"), allow(dead_code))]
fn resolve_database_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--db=") {
            return PathBuf::from(value);
        }
        if arg == "--db" {
            if let Some(value) = args.next() {
                return PathBuf::from(value);
            }
        }
    }
    std::env::var_os("SYSCALL_DB")
        .map(PathBuf::from)
        .unwrap_or_else(default_db_path)
}

#[cfg_attr(not(feature = "desktop-app"), allow(dead_code))]
fn resolve_export_directory() -> PathBuf {
    std::env::var_os("SYSCALL_EXPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_data_dir().join("exports"))
}
