use std::fmt;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, Row};
use syscall_core::paths::{default_data_dir, default_db_path};
use syscall_core::{Event, EventPayload, EventType, RecordingScope, SCHEMA_VERSION};
use tracing::debug;

use crate::error::{Result, StorageError};
use crate::migrations;

const SESSION_SELECT: &str = "
    SELECT s.id, s.schema_version, s.started_at_ns, s.ended_at_ns, s.command,
           s.arguments, s.recording_scope, s.status, s.boot_id, s.kernel_release,
           s.collector_version, s.dropped_events, s.ringbuf_lost_events,
           s.userspace_dropped_events, s.malformed_events, s.filtered_events,
           s.error,
           (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id),
           (SELECT COUNT(DISTINCT e.process_instance_id) FROM events e WHERE e.session_id = s.id)
    FROM sessions s
";

/// Lifecycle state of a recording session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Starting,
    Recording,
    Completed,
    Interrupted,
    Failed,
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
            _ => Self::Unknown,
        }
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
}

/// Full session metadata plus derived counts.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Open (creating if needed) a writable database and apply migrations.
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

        debug!(path = %path.display(), "opened writable database");
        Ok(Self { conn, path })
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
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("database does not exist: {}", path.display()),
            )));
        }
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
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
        let changed = self.conn.execute(
            "UPDATE sessions SET status = ?2 WHERE id = ?1",
            params![id, status.as_str()],
        )?;
        if changed == 0 {
            return Err(StorageError::SessionNotFound(id.to_owned()));
        }
        Ok(())
    }

    /// Finalize a session and record loss/malformed counters.
    pub fn finish_session(&self, id: &str, finish: &SessionFinish) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE sessions SET
                ended_at_ns = ?2,
                status = ?3,
                dropped_events = ?4,
                ringbuf_lost_events = ?5,
                userspace_dropped_events = ?6,
                malformed_events = ?7,
                filtered_events = ?8,
                error = ?9
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
            ],
        )?;
        if changed == 0 {
            return Err(StorageError::SessionNotFound(id.to_owned()));
        }
        Ok(())
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
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (
                    session_id, schema_version, event_type, timestamp_ns, monotonic_ns,
                    pid, tid, ppid, uid, gid, process_instance_id, comm, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            for event in events {
                let payload = serde_json::to_string(&event.payload).map_err(|err| {
                    StorageError::Data(format!("could not encode event payload: {err}"))
                })?;
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
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, session_id, schema_version, event_type, timestamp_ns,
                    monotonic_ns, pid, tid, ppid, uid, gid, process_instance_id,
                    comm, payload
             FROM events
             WHERE session_id = ?1
               AND (?2 IS NULL OR event_type = ?2)
               AND (?3 IS NULL OR pid = ?3)
             ORDER BY timestamp_ns ASC, id ASC
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
        dropped_events: row.get::<_, i64>(11)?.max(0) as u64,
        ringbuf_lost_events: row.get::<_, i64>(12)?.max(0) as u64,
        userspace_dropped_events: row.get::<_, i64>(13)?.max(0) as u64,
        malformed_events: row.get::<_, i64>(14)?.max(0) as u64,
        filtered_events: row.get::<_, i64>(15)?.max(0) as u64,
        error: row.get(16)?,
        event_count: row.get(17)?,
        process_count: row.get(18)?,
    })
}

fn row_to_event(row: &Row<'_>) -> rusqlite::Result<Event> {
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
    if schema_version != SCHEMA_VERSION {
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
    })
}
