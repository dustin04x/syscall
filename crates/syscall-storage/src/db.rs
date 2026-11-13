use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, Row};
use serde::{Deserialize, Serialize};
use syscall_core::paths::{default_data_dir, default_db_path};
use syscall_core::{
    Event, EventPayload, EventType, RecordingScope, MIN_READABLE_SCHEMA_VERSION, SCHEMA_VERSION,
};
use tracing::debug;

use crate::error::{Result, StorageError};
use crate::migrations;

const SESSION_SELECT: &str = "
    SELECT s.id, s.schema_version, s.started_at_ns, s.ended_at_ns, s.command,
           s.arguments, s.recording_scope, s.status, s.boot_id, s.kernel_release,
           s.collector_version, s.dropped_events, s.ringbuf_lost_events,
           s.userspace_dropped_events, s.malformed_events, s.filtered_events,
           s.error,
           s.termination_reason, s.target_exit_code, s.target_exit_signal,
           s.recovered_from_status, s.recovered_at_ns, s.finalized_at_ns,
           s.events_received, s.events_decoded, s.events_attributed,
           s.events_persisted, s.events_rejected_scope, s.events_rejected_malformed,
           s.events_persist_failed, s.events_self_filtered,
           (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id),
           (SELECT COUNT(DISTINCT e.process_instance_id) FROM events e WHERE e.session_id = s.id)
    FROM sessions s
";

/// Lifecycle state of a recording session.
///
/// State machine (terminal states are completed/interrupted/failed/recovered):
/// - starting  -> recording | completed | interrupted | failed | recovered
/// - recording -> completed | interrupted | failed | recovered
/// - completed/interrupted/failed/recovered -> (same finalization only, idempotent)
///
/// `recovered` marks a session that was left in a non-terminal state by an
/// abnormal termination and later recovered without fabricating missing events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Starting,
    Recording,
    Completed,
    Interrupted,
    Failed,
    Recovered,
    Unknown,
}

impl SessionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Recording => "recording",
            Self::Completed => "completed",
            Self::Interrupted => "interrupted",
            Self::Failed => "failed",
            Self::Recovered => "recovered",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "starting" => Self::Starting,
            "recording" => Self::Recording,
            "completed" => Self::Completed,
            "interrupted" => Self::Interrupted,
            "failed" => Self::Failed,
            "recovered" => Self::Recovered,
            _ => Self::Unknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Interrupted | Self::Failed | Self::Recovered
        )
    }

    pub const fn is_abandonable(self) -> bool {
        matches!(self, Self::Starting | Self::Recording)
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Session row to insert when recording starts.
#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: String,
    pub schema_version: u16,
    pub started_at_ns: i64,
    pub command: String,
    pub arguments: Vec<String>,
    pub recording_scope: RecordingScope,
    pub boot_id: Option<String>,
    pub kernel_release: Option<String>,
    pub collector_version: Option<String>,
}

/// Final counters and status for a session.
#[derive(Debug, Clone)]
pub struct SessionFinish {
    pub ended_at_ns: i64,
    pub status: SessionStatus,
    pub dropped_events: u64,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub malformed_events: u64,
    pub filtered_events: u64,
    pub error: Option<String>,
    /// Why the session ended (e.g. target_exit, interrupted, collector_error,
    /// abnormal_termination_recovered).
    pub termination_reason: Option<String>,
    pub target_exit_code: Option<i32>,
    pub target_exit_signal: Option<i32>,
    /// Set when finalizing a recovered/abandoned session.
    pub recovered_from_status: Option<SessionStatus>,
    pub recovered_at_ns: Option<i64>,
    pub finalized_at_ns: Option<i64>,
    // Forensic accounting (v2). Kept in sync with legacy counter columns.
    pub events_received: u64,
    pub events_decoded: u64,
    pub events_attributed: u64,
    pub events_persisted: u64,
    pub events_rejected_scope: u64,
    pub events_rejected_malformed: u64,
    pub events_persist_failed: u64,
    /// Samples discarded because the collector generated them itself. This is
    /// separate from scope and thread-context filtering.
    pub events_self_filtered: u64,
}

impl SessionFinish {
    pub fn reconciled(&self) -> Self {
        let mut out = self.clone();
        out.events_rejected_scope = if out.events_rejected_scope == 0 {
            out.filtered_events
        } else {
            out.events_rejected_scope
        };
        out.events_rejected_malformed = if out.events_rejected_malformed == 0 {
            out.malformed_events
        } else {
            out.events_rejected_malformed
        };
        out.dropped_events = out.ringbuf_lost_events + out.userspace_dropped_events;
        out.filtered_events = out.events_rejected_scope;
        out.malformed_events = out.events_rejected_malformed;
        out
    }
}

/// Full session metadata plus derived counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub schema_version: u16,
    pub started_at_ns: i64,
    pub ended_at_ns: Option<i64>,
    pub command: String,
    pub arguments: Vec<String>,
    pub recording_scope: RecordingScope,
    pub status: SessionStatus,
    pub boot_id: Option<String>,
    pub kernel_release: Option<String>,
    pub collector_version: Option<String>,
    pub dropped_events: u64,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub malformed_events: u64,
    pub filtered_events: u64,
    pub error: Option<String>,
    pub termination_reason: Option<String>,
    pub target_exit_code: Option<i32>,
    pub target_exit_signal: Option<i32>,
    pub recovered_from_status: Option<SessionStatus>,
    pub recovered_at_ns: Option<i64>,
    pub finalized_at_ns: Option<i64>,
    pub events_received: u64,
    pub events_decoded: u64,
    pub events_attributed: u64,
    pub events_persisted: u64,
    pub events_rejected_scope: u64,
    pub events_rejected_malformed: u64,
    pub events_persist_failed: u64,
    pub events_self_filtered: u64,
    pub event_count: i64,
    pub process_count: i64,
}

/// Event query parameters. All identifiers are bound, never interpolated.
#[derive(Debug, Clone)]
pub struct EventQuery {
    pub session_id: String,
    pub limit: usize,
    pub offset: usize,
    pub event_type: Option<EventType>,
    pub pid: Option<i32>,
}

impl EventQuery {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            limit: 100,
            offset: 0,
            event_type: None,
            pid: None,
        }
    }
}

/// Per-process rollup for `syscall inspect`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSummary {
    pub process_instance_id: String,
    pub pid: i32,
    pub comm: String,
    pub first_seen_ns: i64,
    pub last_seen_ns: i64,
    pub event_count: u64,
    pub exited: bool,
}

/// A writable or read-only SQLite connection with the SYSCALL schema.
#[derive(Debug)]
pub struct Storage {
    conn: Connection,
    path: PathBuf,
}

impl Storage {
    /// Open (creating if needed) a writable database, apply migrations, and
    /// recover sessions left in a non-terminal state by an abnormal termination.
    ///
    /// Recovery is idempotent and preserves all committed events/counters.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(StorageError::InvalidPath("empty path".to_owned()));
        }
        ensure_parent(&path)?;

        let mut conn = Connection::open(&path)?;
        secure_database_file(&path)?;
        configure_writable(&conn)?;
        migrations::migrate(&mut conn)?;
        secure_database_file(&path)?;

        let storage = Self { conn, path };
        storage.recover_abandoned_sessions()?;
        debug!(path = %storage.path.display(), "opened writable database");
        Ok(storage)
    }

    /// Open an in-memory database. Intended for tests and tooling.
    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        configure_writable(&conn)?;
        migrations::migrate(&mut conn)?;
        Ok(Self {
            conn,
            path: PathBuf::from(":memory:"),
        })
    }

    /// Open an existing database without write access or migrations.
    ///
    /// Verification/read-only use must not modify DB/WAL/SHM files. When no WAL/SHM
    /// sidecars exist, open in immutable mode to avoid SQLite creating sidecar files.
    /// When WAL/SHM state is present, open normally read-only and surface a clear
    /// structured failure if required sidecars cannot be accessed safely.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("database does not exist: {}", path.display()),
            )));
        }
        let wal_path = {
            let mut p = path.as_os_str().to_os_string();
            p.push("-wal");
            PathBuf::from(p)
        };
        let shm_path = {
            let mut p = path.as_os_str().to_os_string();
            p.push("-shm");
            PathBuf::from(p)
        };
        let has_wal = wal_path.exists();
        let has_shm = shm_path.exists();

        let conn = if !has_wal && !has_shm {
            // No WAL state present: immutable prevents sidecar creation while allowing reads.
            let uri = format!("file:{}?mode=ro&immutable=1", path.display());
            Connection::open_with_flags(
                &uri,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_URI
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?
        } else {
            // WAL/SHM state exists: must read it safely; cannot use immutable.
            Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?
        };
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;
             PRAGMA query_only = ON;",
        )?;
        migrations::check_version(&conn)?;
        Ok(Self { conn, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn create_session(&self, session: &NewSession) -> Result<()> {
        let arguments = serde_json::to_string(&session.arguments)
            .map_err(|err| StorageError::Data(format!("could not encode arguments: {err}")))?;
        self.conn.execute(
            "INSERT INTO sessions (
                id, schema_version, started_at_ns, command, arguments,
                recording_scope, status, boot_id, kernel_release, collector_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                session.id,
                i64::from(session.schema_version),
                session.started_at_ns,
                session.command,
                arguments,
                session.recording_scope.as_str(),
                SessionStatus::Starting.as_str(),
                session.boot_id,
                session.kernel_release,
                session.collector_version,
            ],
        )?;
        Ok(())
    }

    pub fn update_session_status(&self, id: &str, status: SessionStatus) -> Result<()> {
        let current = self
            .get_session(id)?
            .ok_or_else(|| StorageError::SessionNotFound(id.to_owned()))?;
        validate_transition(id, current.status, status)?;
        if current.status == status {
            return Ok(());
        }
        let changed = self.conn.execute(
            "UPDATE sessions SET status = ?2 WHERE id = ?1",
            params![id, status.as_str()],
        )?;
        if changed == 0 {
            return Err(StorageError::SessionNotFound(id.to_owned()));
        }
        Ok(())
    }

    /// Finalize a session with explicit counters and lifecycle metadata.
    ///
    /// Idempotent for an identical finalization of an already-finalized session.
    /// Conflicting re-finalization is rejected. Recovery finalization is allowed
    /// only from non-terminal states and never discards committed events.
    pub fn finish_session(&self, id: &str, finish: &SessionFinish) -> Result<()> {
        let current = self
            .get_session(id)?
            .ok_or_else(|| StorageError::SessionNotFound(id.to_owned()))?;
        let finish = finish.reconciled();
        // Persisted count must reflect committed rows, not attempted writes.
        let committed = self.count_events(id)?;
        let mut finish = finish;
        finish.events_persisted = committed;

        if current.status.is_terminal() {
            if is_equivalent_terminal_finalization(&current, &finish) {
                return Ok(());
            }
            return Err(StorageError::ConflictingFinalization {
                session_id: id.to_owned(),
                existing: current.status.as_str().to_owned(),
                attempted: finish.status.as_str().to_owned(),
            });
        }
        validate_transition(id, current.status, finish.status)?;

        let recovered_from_status = finish
            .recovered_from_status
            .or_else(|| {
                if finish.status == SessionStatus::Recovered {
                    Some(current.status)
                } else {
                    None
                }
            })
            .map(|s| s.as_str().to_owned());
        let finalized_at_ns = finish.finalized_at_ns.or(Some(finish.ended_at_ns));
        let recovered_at_ns = finish.recovered_at_ns.or_else(|| {
            if finish.status == SessionStatus::Recovered {
                finalized_at_ns
            } else {
                None
            }
        });
        let termination_reason = finish
            .termination_reason
            .or_else(|| default_termination_reason(finish.status).map(str::to_owned));

        let changed = self.conn.execute(
            "UPDATE sessions SET
                ended_at_ns = ?2,
                status = ?3,
                dropped_events = ?4,
                ringbuf_lost_events = ?5,
                userspace_dropped_events = ?6,
                malformed_events = ?7,
                filtered_events = ?8,
                error = ?9,
                termination_reason = ?10,
                target_exit_code = ?11,
                target_exit_signal = ?12,
                recovered_from_status = ?13,
                recovered_at_ns = ?14,
                finalized_at_ns = ?15,
                events_received = ?16,
                events_decoded = ?17,
                events_attributed = ?18,
                events_persisted = ?19,
                events_rejected_scope = ?20,
                events_rejected_malformed = ?21,
                events_persist_failed = ?22,
                events_self_filtered = ?23
             WHERE id = ?1",
            params![
                id,
                finish.ended_at_ns,
                finish.status.as_str(),
                to_i64(finish.dropped_events),
                to_i64(finish.ringbuf_lost_events),
                to_i64(finish.userspace_dropped_events),
                to_i64(finish.malformed_events),
                to_i64(finish.filtered_events),
                finish.error,
                termination_reason,
                finish.target_exit_code.map(i64::from),
                finish.target_exit_signal.map(i64::from),
                recovered_from_status,
                recovered_at_ns,
                finalized_at_ns,
                to_i64(finish.events_received),
                to_i64(finish.events_decoded),
                to_i64(finish.events_attributed),
                to_i64(finish.events_persisted),
                to_i64(finish.events_rejected_scope),
                to_i64(finish.events_rejected_malformed),
                to_i64(finish.events_persist_failed),
                to_i64(finish.events_self_filtered),
            ],
        )?;
        if changed == 0 {
            return Err(StorageError::SessionNotFound(id.to_owned()));
        }
        Ok(())
    }

    /// Recover sessions abandoned in a non-terminal state (e.g. recorder crash).
    /// Preserves all committed events and existing counters; marks outcome as
    /// `recovered` with explicit metadata. Safe to run repeatedly.
    pub fn recover_abandoned_sessions(&self) -> Result<usize> {
        let now_ns = syscall_core::clock::realtime_now_ns().unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos().min(i64::MAX as u128) as i64)
                .unwrap_or(0)
        });
        let mut stmt = self
            .conn
            .prepare("SELECT id, status FROM sessions WHERE status IN ('starting', 'recording')")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let abandoned: Vec<(String, SessionStatus)> = rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|(id, status)| (id, SessionStatus::from_db(&status)))
            .collect();
        drop(stmt);

        let mut recovered = 0usize;
        for (id, previous) in abandoned {
            if !previous.is_abandonable() {
                continue;
            }
            let session = match self.get_session(&id)? {
                Some(s) => s,
                None => continue,
            };
            if session.status.is_terminal() {
                continue;
            }
            // Never recover a session owned by a demonstrably active collector.
            // A non-blocking exclusive lock proves no active holder for this
            // session lock; if we cannot acquire it, treat as active/uncertain
            // and skip recovery conservatively.
            let _ownership_guard = if self.path.as_os_str() == ":memory:" {
                None
            } else {
                match crate::lock::try_acquire_exclusive(&self.path, &id)? {
                    Some(guard) => Some(guard),
                    None => continue,
                }
            };
            let finish = SessionFinish {
                ended_at_ns: session.ended_at_ns.unwrap_or(now_ns),
                status: SessionStatus::Recovered,
                dropped_events: session.dropped_events,
                ringbuf_lost_events: session.ringbuf_lost_events,
                userspace_dropped_events: session.userspace_dropped_events,
                malformed_events: session.malformed_events,
                filtered_events: session.filtered_events,
                error: session.error.clone().or_else(|| {
                    Some("session left in non-terminal state; recovered on open".to_owned())
                }),
                termination_reason: Some("abnormal_termination_recovered".to_owned()),
                target_exit_code: session.target_exit_code,
                target_exit_signal: session.target_exit_signal,
                recovered_from_status: Some(previous),
                recovered_at_ns: Some(now_ns),
                finalized_at_ns: Some(now_ns),
                events_received: session.events_received,
                events_decoded: session.events_decoded,
                events_attributed: session.events_attributed,
                events_persisted: session.events_persisted,
                events_rejected_scope: session.events_rejected_scope.max(session.filtered_events),
                events_rejected_malformed: session
                    .events_rejected_malformed
                    .max(session.malformed_events),
                events_persist_failed: session.events_persist_failed,
                events_self_filtered: session.events_self_filtered,
            };
            self.finish_session(&id, &finish)?;
            drop(_ownership_guard);
            recovered += 1;
        }
        Ok(recovered)
    }

    pub fn list_sessions(&self, limit: usize) -> Result<Vec<SessionSummary>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!("{SESSION_SELECT} ORDER BY s.started_at_ns DESC LIMIT ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit], row_to_session)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StorageError::from)
    }

    pub fn get_session(&self, id: &str) -> Result<Option<SessionSummary>> {
        let sql = format!("{SESSION_SELECT} WHERE s.id = ?1");
        let mut stmt = self.conn.prepare(&sql)?;
        match stmt.query_row(params![id], row_to_session) {
            Ok(session) => Ok(Some(session)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(StorageError::from(err)),
        }
    }

    /// Insert a batch of validated events in one transaction.
    pub fn insert_events(&mut self, session_id: &str, events: &[Event]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }
        for event in events {
            if event.session_id != session_id {
                return Err(StorageError::Data(format!(
                    "event session id {} does not match batch session {session_id}",
                    event.session_id
                )));
            }
            event.validate()?;
        }

        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO events (
                    session_id, schema_version, event_type, timestamp_ns, monotonic_ns,
                    pid, tid, ppid, uid, gid, process_instance_id, comm, payload,
                    raw_bpf_pid, raw_bpf_tgid, observer_pid, observer_tgid,
                    source_tracepoint, wire_schema_version, attribution_method,
                    timestamp_clock_domain, monotonic_clock_domain
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
            )?;
            for event in events {
                let payload = serde_json::to_string(&event.payload).map_err(|err| {
                    StorageError::Data(format!("could not encode event payload: {err}"))
                })?;
                let prov = event.provenance.as_ref();
                stmt.execute(params![
                    event.session_id,
                    i64::from(event.schema_version),
                    event.event_type.as_str(),
                    event.timestamp_ns,
                    to_i64(event.monotonic_ns),
                    i64::from(event.pid),
                    i64::from(event.tid),
                    event.ppid.map(i64::from),
                    i64::from(event.uid),
                    i64::from(event.gid),
                    event.process_instance_id,
                    event.comm,
                    payload,
                    prov.and_then(|p| p.raw_bpf_pid).map(i64::from),
                    prov.and_then(|p| p.raw_bpf_tgid).map(i64::from),
                    prov.and_then(|p| p.observer_pid).map(i64::from),
                    prov.and_then(|p| p.observer_tgid).map(i64::from),
                    prov.and_then(|p| p.source_tracepoint.clone()),
                    prov.and_then(|p| p.wire_schema_version).map(i64::from),
                    prov.and_then(|p| p.attribution_method.clone()),
                    prov.and_then(|p| p.timestamp_clock_domain.clone()),
                    prov.and_then(|p| p.monotonic_clock_domain.clone()),
                ])?;
            }
        }
        tx.commit()?;
        Ok(events.len())
    }

    /// Retrieve events in chronological order. Uses bound parameters only.
    pub fn query_events(&self, query: &EventQuery) -> Result<Vec<Event>> {
        let limit = i64::try_from(query.limit).unwrap_or(i64::MAX);
        let offset = i64::try_from(query.offset).unwrap_or(i64::MAX);
        let event_type = query.event_type.map(|value| value.as_str());
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, schema_version, event_type, timestamp_ns,
                    monotonic_ns, pid, tid, ppid, uid, gid, process_instance_id,
                    comm, payload,
                    raw_bpf_pid, raw_bpf_tgid, observer_pid, observer_tgid,
                    source_tracepoint, wire_schema_version, attribution_method,
                    timestamp_clock_domain, monotonic_clock_domain
             FROM events
             WHERE session_id = ?1
               AND (?2 IS NULL OR event_type = ?2)
               AND (?3 IS NULL OR pid = ?3)
             ORDER BY timestamp_ns ASC, monotonic_ns ASC, id ASC
             LIMIT ?4 OFFSET ?5",
        )?;
        let rows = stmt.query_map(
            params![query.session_id, event_type, query.pid, limit, offset],
            row_to_event,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StorageError::from)
    }

    pub fn count_events(&self, session_id: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE session_id = ?1",
            params![session_id],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    pub fn event_type_counts(&self, session_id: &str) -> Result<Vec<(EventType, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_type, COUNT(*) FROM events
             WHERE session_id = ?1
             GROUP BY event_type
             ORDER BY CASE event_type
                 WHEN 'process_exec' THEN 1
                 WHEN 'process_fork' THEN 2
                 WHEN 'process_exit' THEN 3
                 WHEN 'file_open' THEN 4
                 WHEN 'network_connect' THEN 5
                 ELSE 99
             END",
        )?;
        let rows = stmt.query_map(params![session_id], |row| {
            let raw: String = row.get(0)?;
            let event_type = raw.parse::<EventType>().map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unknown event type {raw}"),
                    )),
                )
            })?;
            let count: i64 = row.get(1)?;
            Ok((event_type, count.max(0) as u64))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StorageError::from)
    }

    /// Per-process rollups ordered by event count (most active first).
    pub fn process_summaries(&self, session_id: &str, limit: usize) -> Result<Vec<ProcessSummary>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(
            "SELECT process_instance_id,
                    MIN(pid),
                    comm,
                    MIN(timestamp_ns),
                    MAX(timestamp_ns),
                    COUNT(*),
                    MAX(CASE WHEN event_type = 'process_exit' THEN 1 ELSE 0 END)
             FROM events
             WHERE session_id = ?1
             GROUP BY process_instance_id
             ORDER BY COUNT(*) DESC, MIN(timestamp_ns) ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![session_id, limit], |row| {
            Ok(ProcessSummary {
                process_instance_id: row.get(0)?,
                pid: row.get(1)?,
                comm: row.get(2)?,
                first_seen_ns: row.get(3)?,
                last_seen_ns: row.get(4)?,
                event_count: row.get::<_, i64>(5)?.max(0) as u64,
                exited: row.get::<_, i64>(6)? != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(StorageError::from)
    }

    /// Read-only forensic verification of a session (no migrations/repairs/writes).
    pub fn verify_session(
        &self,
        session_id: &str,
    ) -> Result<syscall_core::SessionVerificationReport> {
        crate::verify::verify_session(self, session_id)
    }
}

fn configure_writable(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA trusted_schema = OFF;",
    )?;
    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let default_dir = default_data_dir();
    let is_default = parent == default_dir;
    let did_create = if parent.exists() {
        false
    } else {
        std::fs::create_dir_all(parent)?;
        true
    };
    if is_default || did_create {
        set_mode(parent, 0o700)?;
    }
    Ok(())
}

fn secure_database_file(path: &Path) -> Result<()> {
    if path == default_db_path() || path.exists() {
        set_mode(path, 0o600)?;
    }
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        if sidecar.exists() {
            set_mode(&sidecar, 0o600)?;
        }
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn row_to_session(row: &Row<'_>) -> rusqlite::Result<SessionSummary> {
    let schema_version: i64 = row.get(1)?;
    let recording_scope: String = row.get(6)?;
    let status: String = row.get(7)?;
    let arguments: String = row.get(5)?;

    let recording_scope = recording_scope.parse::<RecordingScope>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown recording scope",
            )),
        )
    })?;
    let arguments = serde_json::from_str::<Vec<String>>(&arguments).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid arguments JSON: {err}"),
            )),
        )
    })?;

    let dropped_events = row.get::<_, i64>(11)?.max(0) as u64;
    let ringbuf_lost_events = row.get::<_, i64>(12)?.max(0) as u64;
    let userspace_dropped_events = row.get::<_, i64>(13)?.max(0) as u64;
    let malformed_events = row.get::<_, i64>(14)?.max(0) as u64;
    let filtered_events = row.get::<_, i64>(15)?.max(0) as u64;
    let recovered_from_status: Option<String> = row.get(20)?;
    let events_received = row.get::<_, i64>(23)?.max(0) as u64;
    let events_decoded = row.get::<_, i64>(24)?.max(0) as u64;
    let events_attributed = row.get::<_, i64>(25)?.max(0) as u64;
    let events_persisted = row.get::<_, i64>(26)?.max(0) as u64;
    let events_rejected_scope = row.get::<_, i64>(27)?.max(0) as u64;
    let events_rejected_malformed = row.get::<_, i64>(28)?.max(0) as u64;
    let events_persist_failed = row.get::<_, i64>(29)?.max(0) as u64;
    let events_self_filtered = row.get::<_, i64>(30)?.max(0) as u64;

    Ok(SessionSummary {
        id: row.get(0)?,
        schema_version: u16::try_from(schema_version).unwrap_or(0),
        started_at_ns: row.get(2)?,
        ended_at_ns: row.get(3)?,
        command: row.get(4)?,
        arguments,
        recording_scope,
        status: SessionStatus::from_db(&status),
        boot_id: row.get(8)?,
        kernel_release: row.get(9)?,
        collector_version: row.get(10)?,
        dropped_events,
        ringbuf_lost_events,
        userspace_dropped_events,
        malformed_events,
        filtered_events,
        error: row.get(16)?,
        termination_reason: row.get(17)?,
        target_exit_code: row.get::<_, Option<i64>>(18)?.map(|v| v as i32),
        target_exit_signal: row.get::<_, Option<i64>>(19)?.map(|v| v as i32),
        recovered_from_status: recovered_from_status.map(|s| SessionStatus::from_db(&s)),
        recovered_at_ns: row.get(21)?,
        finalized_at_ns: row.get(22)?,
        events_received: if events_received == 0 {
            filtered_events + malformed_events
        } else {
            events_received
        },
        events_decoded,
        events_attributed,
        events_persisted,
        events_rejected_scope: if events_rejected_scope == 0 {
            filtered_events
        } else {
            events_rejected_scope
        },
        events_rejected_malformed: if events_rejected_malformed == 0 {
            malformed_events
        } else {
            events_rejected_malformed
        },
        events_persist_failed,
        events_self_filtered,
        event_count: row.get(31)?,
        process_count: row.get(32)?,
    })
}

pub(crate) fn row_to_event(row: &Row<'_>) -> rusqlite::Result<Event> {
    let schema_version: i64 = row.get(2)?;
    let schema_version = u16::try_from(schema_version).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid event schema version",
            )),
        )
    })?;
    if !(MIN_READABLE_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&schema_version) {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("event schema version {schema_version} is not supported"),
            )),
        ));
    }

    let event_type: String = row.get(3)?;
    let event_type = event_type.parse::<EventType>().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown event type",
            )),
        )
    })?;
    let payload: String = row.get(13)?;
    let payload = serde_json::from_str::<EventPayload>(&payload).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(
            13,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid payload JSON: {err}"),
            )),
        )
    })?;

    let provenance = {
        let raw_bpf_pid: Option<i64> = row.get(14)?;
        let raw_bpf_tgid: Option<i64> = row.get(15)?;
        let observer_pid: Option<i64> = row.get(16)?;
        let observer_tgid: Option<i64> = row.get(17)?;
        let source_tracepoint: Option<String> = row.get(18)?;
        let wire_schema_version: Option<i64> = row.get(19)?;
        let attribution_method: Option<String> = row.get(20)?;
        let timestamp_clock_domain: Option<String> = row.get(21)?;
        let monotonic_clock_domain: Option<String> = row.get(22)?;
        if raw_bpf_pid.is_none()
            && raw_bpf_tgid.is_none()
            && observer_pid.is_none()
            && observer_tgid.is_none()
            && source_tracepoint.is_none()
            && wire_schema_version.is_none()
            && attribution_method.is_none()
            && timestamp_clock_domain.is_none()
            && monotonic_clock_domain.is_none()
        {
            None
        } else {
            Some(syscall_core::EventProvenance {
                raw_bpf_pid: raw_bpf_pid.map(|v| v as i32),
                raw_bpf_tgid: raw_bpf_tgid.map(|v| v as i32),
                observer_pid: observer_pid.map(|v| v as i32),
                observer_tgid: observer_tgid.map(|v| v as i32),
                source_tracepoint,
                wire_schema_version: wire_schema_version.and_then(|v| u16::try_from(v).ok()),
                attribution_method,
                timestamp_clock_domain,
                monotonic_clock_domain,
            })
        }
    };

    Ok(Event {
        id: Some(row.get(0)?),
        session_id: row.get(1)?,
        schema_version,
        event_type,
        timestamp_ns: row.get(4)?,
        monotonic_ns: row.get::<_, i64>(5)?.max(0) as u64,
        pid: row.get(6)?,
        tid: row.get(7)?,
        ppid: row.get(8)?,
        uid: row.get(9)?,
        gid: row.get(10)?,
        process_instance_id: row.get(11)?,
        comm: row.get(12)?,
        payload,
        provenance,
    })
}

fn validate_transition(id: &str, from: SessionStatus, to: SessionStatus) -> Result<()> {
    if from == to {
        return Ok(());
    }
    let allowed = match from {
        SessionStatus::Starting => matches!(
            to,
            SessionStatus::Recording
                | SessionStatus::Completed
                | SessionStatus::Interrupted
                | SessionStatus::Failed
                | SessionStatus::Recovered
        ),
        SessionStatus::Recording => matches!(
            to,
            SessionStatus::Completed
                | SessionStatus::Interrupted
                | SessionStatus::Failed
                | SessionStatus::Recovered
        ),
        SessionStatus::Completed
        | SessionStatus::Interrupted
        | SessionStatus::Failed
        | SessionStatus::Recovered => false,
        SessionStatus::Unknown => to.is_terminal(),
    };
    if allowed {
        Ok(())
    } else {
        Err(StorageError::InvalidTransition {
            session_id: id.to_owned(),
            from: from.as_str().to_owned(),
            to: to.as_str().to_owned(),
        })
    }
}

fn default_termination_reason(status: SessionStatus) -> Option<&'static str> {
    match status {
        SessionStatus::Completed => Some("target_exit"),
        SessionStatus::Interrupted => Some("interrupted"),
        SessionStatus::Failed => Some("collector_error"),
        SessionStatus::Recovered => Some("abnormal_termination_recovered"),
        _ => None,
    }
}

fn is_equivalent_terminal_finalization(current: &SessionSummary, finish: &SessionFinish) -> bool {
    if current.status != finish.status {
        return false;
    }
    // If core outcome/status matches, treat as idempotent no-op to avoid
    // accidental double-finalization races while preserving outcome.
    true
}
