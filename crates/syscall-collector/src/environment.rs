//! Read-only environment inspection used by `syscall info`.
//!
//! Nothing here loads BPF or requires root. Capabilities that cannot be proven
//! without privilege are reported as unknown, not as passing.

use std::path::{Path, PathBuf};

use syscall_core::paths::default_db_path;
use syscall_core::{EventType, SCHEMA_VERSION};

use crate::privilege::{self, PrivilegeStatus};
use crate::procfs;

const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];
const TRACEPOINTS: [&str; 3] = [
    "sched_process_exec",
    "sched_process_fork",
    "sched_process_exit",
];

#[derive(Debug, Clone)]
pub struct TracepointStatus {
    pub name: &'static str,
    pub available: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct EnvironmentReport {
    pub os_release: Option<String>,
    pub kernel_release: Option<String>,
    pub is_wsl: bool,
    /// Core/session/event payload schema version (SQLite + domain model).
    pub core_schema_version: u16,
    /// BPF ring-buffer wire format schema version.
    pub wire_schema_version: u16,
    pub btf_path: &'static str,
    pub btf_available: bool,
    pub tracefs_root: Option<String>,
    pub tracefs_events_readable: bool,
    pub tracepoints: Vec<TracepointStatus>,
    pub ringbuf_kernel_support: bool,
    pub privilege: PrivilegeStatus,
    pub database_path: PathBuf,
    pub database_exists: bool,
    pub collected_event_types: Vec<EventType>,
    pub schema_only_event_types: Vec<EventType>,
}

pub fn inspect(database_path: Option<PathBuf>) -> EnvironmentReport {
    let privilege = privilege::inspect();
    let tracefs_root = TRACEFS_ROOTS
        .iter()
        .find(|root| Path::new(root).exists())
        .map(|root| (*root).to_owned());
    let tracefs_events_readable = tracefs_root
        .as_deref()
        .map(|root| Path::new(root).join("events/sched").is_dir())
        .unwrap_or(false);

    let tracepoints = TRACEPOINTS
        .iter()
        .map(|name| TracepointStatus {
            name,
            available: if tracefs_events_readable {
                tracefs_root
                    .as_deref()
                    .map(|root| Path::new(root).join("events/sched").join(name).is_dir())
            } else {
                None
            },
        })
        .collect();

    let database_path = database_path.unwrap_or_else(default_db_path);
    let database_exists = database_path.is_file();

    EnvironmentReport {
        os_release: procfs::read_os_release(),
        kernel_release: procfs::read_kernel_release(),
        is_wsl: procfs::is_wsl(),
        core_schema_version: SCHEMA_VERSION,
        wire_schema_version: crate::event_decoder::WIRE_SCHEMA_VERSION,
        btf_path: privilege.btf_path,
        btf_available: privilege.btf_available,
        tracefs_root,
        tracefs_events_readable,
        tracepoints,
        ringbuf_kernel_support: kernel_supports_ringbuf(procfs::read_kernel_release().as_deref()),
        privilege,
        database_path,
        database_exists,
        collected_event_types: EventType::COLLECTED.to_vec(),
        schema_only_event_types: EventType::ALL
            .iter()
            .copied()
            .filter(|event_type| !event_type.is_collected())
            .collect(),
    }
}

fn kernel_supports_ringbuf(release: Option<&str>) -> bool {
    let Some(release) = release else {
        return false;
    };
    let mut parts = release.split('.');
    let major = parts.next().and_then(|value| value.parse::<u32>().ok());
    let minor = parts.next().and_then(|value| value.parse::<u32>().ok());
    match (major, minor) {
        (Some(major), Some(minor)) => major > 5 || (major == 5 && minor >= 8),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ringbuf_version_check() {
        assert!(kernel_supports_ringbuf(Some(
            "6.6.87.2-microsoft-standard-WSL2"
        )));
        assert!(kernel_supports_ringbuf(Some("5.8.0")));
        assert!(!kernel_supports_ringbuf(Some("5.7.0")));
        assert!(!kernel_supports_ringbuf(None));
    }

    #[test]
    fn inspect_reports_event_types() {
        let report = inspect(Some(PathBuf::from("/nonexistent/syscall.db")));
        assert_eq!(report.core_schema_version, SCHEMA_VERSION);
        assert_eq!(report.collected_event_types.len(), 3);
        assert_eq!(report.schema_only_event_types.len(), 2);
        assert!(!report.database_exists);
    }
}
