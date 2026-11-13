use std::sync::Arc;

use syscall_core::{AnalysisReport, SessionVerificationReport};
use tauri::State;

use crate::contract::*;
use crate::error::{CommandError, DesktopError};
use crate::service::DesktopService;

pub struct AppState {
    pub service: Arc<DesktopService>,
}

async fn blocking<T, F>(work: F) -> Result<T, CommandError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, DesktopError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|err| CommandError {
            code: "INTERNAL_ERROR",
            message: format!("background task failed: {err}"),
        })?
        .map_err(CommandError::from)
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    state.service.app_info()
}

#[tauri::command]
pub async fn list_sessions(
    state: State<'_, AppState>,
    request: ListSessionsRequest,
) -> Result<SessionListResponse, CommandError> {
    let service = state.service.clone();
    blocking(move || service.list_sessions(request)).await
}

#[tauri::command]
pub async fn get_overview(
    state: State<'_, AppState>,
    request: OverviewRequest,
) -> Result<OverviewResponse, CommandError> {
    let service = state.service.clone();
    blocking(move || service.overview(request)).await
}

#[tauri::command]
pub async fn get_session(
    state: State<'_, AppState>,
    request: SessionRequest,
) -> Result<SessionDetail, CommandError> {
    let service = state.service.clone();
    blocking(move || service.get_session(request)).await
}

#[tauri::command]
pub async fn list_processes(
    state: State<'_, AppState>,
    request: SessionRequest,
) -> Result<ProcessTreeResponse, CommandError> {
    let service = state.service.clone();
    blocking(move || service.list_processes(request)).await
}

#[tauri::command]
pub async fn query_timeline(
    state: State<'_, AppState>,
    request: TimelineRequest,
) -> Result<TimelineResponse, CommandError> {
    let service = state.service.clone();
    blocking(move || service.query_timeline(request)).await
}

#[tauri::command]
pub async fn query_filesystem(
    state: State<'_, AppState>,
    request: ActivityRequest,
) -> Result<FileActivityResponse, CommandError> {
    let service = state.service.clone();
    blocking(move || service.query_filesystem(request)).await
}

#[tauri::command]
pub async fn query_network(
    state: State<'_, AppState>,
    request: ActivityRequest,
) -> Result<ConnectionResponse, CommandError> {
    let service = state.service.clone();
    blocking(move || service.query_network(request)).await
}

#[tauri::command]
pub async fn get_event(
    state: State<'_, AppState>,
    request: EventRequest,
) -> Result<EvidenceDetail, CommandError> {
    let service = state.service.clone();
    blocking(move || service.get_event(request)).await
}

#[tauri::command]
pub async fn run_analysis(
    state: State<'_, AppState>,
    request: SessionRequest,
) -> Result<AnalysisReport, CommandError> {
    let service = state.service.clone();
    blocking(move || service.run_analysis(request)).await
}

#[tauri::command]
pub async fn run_verification(
    state: State<'_, AppState>,
    request: SessionRequest,
) -> Result<SessionVerificationReport, CommandError> {
    let service = state.service.clone();
    blocking(move || service.run_verification(request)).await
}

#[tauri::command]
pub async fn export_session(
    state: State<'_, AppState>,
    request: ExportRequest,
) -> Result<ExportResult, CommandError> {
    let service = state.service.clone();
    blocking(move || service.export_session(request)).await
}
