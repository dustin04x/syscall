//! Read-only forensic verification of recorded sessions.
//!
//! Verification never modifies the database: no migrations, no repairs, no
//! recovery, no event rewrites, and no provenance completion.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use syscall_core::clock;
use syscall_core::verify::{
    FindingSeverity, SessionVerificationReport, SeverityCounts, VerificationAssessment,
    VerificationFinding,
};
use syscall_core::{AddressFamily, EventPayload, EventType};

use crate::db::{SessionStatus, SessionSummary, Storage};
use crate::error::{Result, StorageError};
use crate::migrations::LATEST_SCHEMA_VERSION;

const EVENT_PAGE_SIZE: i64 = 500;
/// Hard cap on materialized findings to prevent unbounded memory use from a
/// malicious/corrupt database. Truncation is reported explicitly.
const MAX_FINDINGS: usize = 5000;

#[derive(Clone)]
struct FindingSink {
    findings: Vec<VerificationFinding>,
    truncated: bool,
    dropped: usize,
}

impl FindingSink {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            truncated: false,
            dropped: 0,
        }
    }

    fn push(&mut self, finding: VerificationFinding) {
        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
        } else {
            self.truncated = true;
            self.dropped += 1;
        }
    }

    fn any_code(&self, code: &str) -> bool {
        self.findings.iter().any(|f| f.code == code)
    }

    fn into_vec(mut self, session_id: &str) -> Vec<VerificationFinding> {
        if self.truncated {
            // Ensure truncation is explicitly reported (bounded).
            if self.findings.len() >= MAX_FINDINGS {
                self.findings.truncate(MAX_FINDINGS.saturating_sub(1));
            }
            self.findings.push(finding(
                "FINDINGS_TRUNCATED",
                FindingSeverity::Warning,
                "Verification findings were truncated",
                "The number of findings exceeded the in-memory safety bound.",
                Some(session_id.to_owned()),
                None,
                None,
                vec![format!(
                    "max_findings={MAX_FINDINGS} dropped={}",
                    self.dropped
                )],
                "Treat the report as partial; inspect the database offline for remaining issues.",
            ));
        }
        self.findings
    }
}

pub fn verify_session(storage: &Storage, session_id: &str) -> Result<SessionVerificationReport> {
    verify_session_conn(storage.connection(), session_id, None)
}

/// Verify a session at `path` without performing migrations, recovery, repair,
/// or schema-changing writes. If the schema is unsupported but its version can
/// be read safely, returns an `unable_to_verify` report with `DB_SCHEMA_UNSUPPORTED`.
/// If even basic schema inspection/open is impossible, returns a stable error.
pub fn verify_session_at_path(
    path: impl AsRef<Path>,
    session_id: &str,
) -> Result<SessionVerificationReport> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("database does not exist: {}", path.display()),
        )));
    }
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(err) => {
            return Err(StorageError::Data(format!(
                "unable_to_verify: could not open database read-only: {err}"
            )));
        }
    };
    // Read-only defensive pragmas. No WAL checkpoint/recovery/normalization.
    let _ = conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;
         PRAGMA query_only = ON;",
    );

    let db_schema_version = match read_user_version(&conn) {
        Ok(v) => v,
        Err(err) => {
            return Err(StorageError::Data(format!(
                "unable_to_verify: schema inspection failed (user_version unreadable): {err}"
            )));
        }
    };

    if db_schema_version == 0 || db_schema_version > LATEST_SCHEMA_VERSION {
        // Cannot trust or query schema-specific structures safely.
        let mut sink = FindingSink::new();
        let mut limitations = Vec::new();
        run_db_integrity_checks(&conn, session_id, &mut sink, &mut limitations);
        // Do not inspect required tables/columns or query session/event data for unsupported schemas.
        let code = if db_schema_version == 0 {
            "DB_SCHEMA_MISSING"
        } else {
            "DB_SCHEMA_UNSUPPORTED"
        };
        let (severity, title, detail, rec) = if db_schema_version == 0 {
            (
                FindingSeverity::Error,
                "Database schema is not initialized",
                "PRAGMA user_version is 0; required SYSCALL schema is missing.".to_owned(),
                "Select a valid SYSCALL database or initialize it via a supported recording flow.",
            )
        } else {
            (
                FindingSeverity::Error,
                "Database schema version is unsupported by this build",
                format!(
                    "Database schema v{db_schema_version} is newer than supported v{LATEST_SCHEMA_VERSION}."
                ),
                "Use a newer SYSCALL build to verify this database; do not assume semantic correctness.",
            )
        };
        sink.push(finding(
            code,
            severity,
            title,
            detail,
            Some(session_id.to_owned()),
            None,
            None,
            vec![
                format!("db_schema_version={db_schema_version}"),
                format!("supported_max={LATEST_SCHEMA_VERSION}"),
            ],
            rec,
        ));
        limitations.push(
            "Schema is missing/unsupported for this build; semantic session/event checks were not performed."
                .to_owned(),
        );
        limitations.push(
            "Verification is read-only and does not prove cryptographic authenticity or tamper-proofing."
                .to_owned(),
        );
        let findings = sink.into_vec(session_id);
        let mut severity_counts = SeverityCounts::default();
        for f in &findings {
            severity_counts.add(f.severity);
        }
        let verification_timestamp_ns = clock::realtime_now_ns().unwrap_or(0);
        // unable_to_verify per spec (required checks cannot be completed / semantic trust unavailable)
        let assessment = VerificationAssessment::UnableToVerify;
        // But compute? spec says unable_to_verify used when required checks cannot be completed.
        return Ok(SessionVerificationReport {
            session_id: session_id.to_owned(),
            verification_timestamp_ns,
            database_schema_version: db_schema_version,
            session_status: None,
            assessment,
            severity_counts,
            findings,
            limitations,
        });
    }

    // Supported schema: reuse normal verification path over this read-only connection.
    verify_session_conn(&conn, session_id, Some(db_schema_version))
}

fn verify_session_conn(
    conn: &Connection,
    session_id: &str,
    known_schema: Option<u32>,
) -> Result<SessionVerificationReport> {
    // Defense-in-depth: enforce read-only query mode if possible.
    let _ = conn.execute_batch("PRAGMA query_only = ON;");

    let mut sink = FindingSink::new();
    let mut limitations: Vec<String> = Vec::new();
    let mut unable = false;

    let db_schema_version = match known_schema {
        Some(v) => v,
        None => match read_user_version(conn) {
            Ok(v) => v,
            Err(err) => {
                sink.push(finding(
                    "DB_SCHEMA_INSPECTION_FAILED",
                    FindingSeverity::Critical,
                    "Database schema version could not be read",
                    format!("PRAGMA user_version failed: {err}"),
                    Some(session_id.to_owned()),
                    None,
                    None,
                    vec![],
                    "Treat the database as unverifiable until inspected manually.",
                ));
                unable = true;
                0
            }
        },
    };

    run_db_integrity_checks(conn, session_id, &mut sink, &mut limitations);
    run_schema_checks(
        conn,
        session_id,
        db_schema_version,
        &mut sink,
        &mut limitations,
    );

    let session = match read_session(conn, session_id) {
        Ok(s) => s,
        Err(err) => {
            sink.push(finding(
                "SESSION_READ_FAILED",
                FindingSeverity::Critical,
                "Session could not be read",
                format!("Reading session metadata failed: {err}"),
                Some(session_id.to_owned()),
                None,
                None,
                vec![],
                "Treat session metadata as unverifiable; inspect database integrity and schema compatibility.",
            ));
            unable = true;
            None
        }
    };

    let session_status = session.as_ref().map(|s| s.status.as_str().to_owned());
    if let Some(session) = session.as_ref() {
        check_session(session, &mut sink);
        check_events_and_accounting(conn, session, &mut sink, &mut limitations, &mut unable);
    } else if !sink.any_code("SESSION_READ_FAILED") {
        sink.push(finding(
            "SESSION_NOT_FOUND",
            FindingSeverity::Error,
            "Session does not exist",
            "The requested session ID was not found in the database.",
            Some(session_id.to_owned()),
            None,
            None,
            vec![],
            "Verify the session ID (e.g. via `syscall sessions`) and ensure the correct database is selected.",
        ));
    }

    // If schema is unsupported for this build, we cannot fully trust semantic checks.
    if db_schema_version > LATEST_SCHEMA_VERSION || db_schema_version == 0 {
        unable = true;
    }

    let mut findings = sink.into_vec(session_id);
    // If truncated marker not already present but dropped happened, ensure explicit note
    // (into_vec handles normal case; if exactly at cap, add limitation)
    if findings.len() > MAX_FINDINGS {
        findings.truncate(MAX_FINDINGS);
    }

    let assessment = compute_assessment(&findings, unable);
    let mut severity_counts = SeverityCounts::default();
    for f in &findings {
        severity_counts.add(f.severity);
    }
    let verification_timestamp_ns = clock::realtime_now_ns().unwrap_or(0);
    if unable
        && !limitations
            .iter()
            .any(|l| l.to_lowercase().contains("unable"))
    {
        limitations.push(
            "Verification could not be completed for all required checks; results may be partial."
                .to_owned(),
        );
    }
    if assessment == VerificationAssessment::UnableToVerify
        && !limitations
            .iter()
            .any(|l| l.to_lowercase().contains("unable"))
    {
        limitations.push("Verification was unable to complete required checks.".to_owned());
    }

    Ok(SessionVerificationReport {
        session_id: session_id.to_owned(),
        verification_timestamp_ns,
        database_schema_version: db_schema_version,
        session_status,
        assessment,
        severity_counts,
        findings,
        limitations,
    })
}

fn compute_assessment(findings: &[VerificationFinding], unable: bool) -> VerificationAssessment {
    // Genuine contradictions/corruption take precedence.
    if findings.iter().any(|f| {
        matches!(
            f.severity,
            FindingSeverity::Error | FindingSeverity::Critical
        )
    }) {
        return VerificationAssessment::Invalid;
    }
    // Required checks could not be completed sufficiently.
    if unable {
        return VerificationAssessment::UnableToVerify;
    }
    let has_warning = findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Warning);
    if !has_warning {
        return VerificationAssessment::Valid;
    }
    let incomplete = findings.iter().any(|f| {
        matches!(
            f.code.as_str(),
            "SESSION_RECOVERED"
                | "SESSION_INCOMPLETE"
                | "EVIDENCE_LOSS_RINGBUF"
                | "EVIDENCE_LOSS_USERSPACE"
                | "ACCOUNTING_INCOMPLETE"
                | "ACCOUNTING_UNAVAILABLE_LEGACY"
                | "PROVENANCE_UNAVAILABLE_LEGACY"
                | "PROVENANCE_UNAVAILABLE"
                | "FORK_IDENTITY_UNRESOLVED"
                | "SESSION_RECOVERY_METADATA_MISSING"
                | "EVENT_SCAN_TRUNCATED"
                | "FINDINGS_TRUNCATED"
        )
    });
    if incomplete {
        VerificationAssessment::ValidButIncomplete
    } else {
        VerificationAssessment::Warning
    }
}

fn run_db_integrity_checks(
    conn: &Connection,
    session_id: &str,
    findings: &mut FindingSink,
    limitations: &mut Vec<String>,
) {
    match conn.query_row("PRAGMA integrity_check(1)", [], |row| {
        row.get::<_, String>(0)
    }) {
        Ok(result) if result.eq_ignore_ascii_case("ok") => {}
        Ok(result) => {
            findings.push(finding(
                "DB_INTEGRITY_CHECK_FAILED",
                FindingSeverity::Critical,
                "SQLite integrity check failed",
                format!("PRAGMA integrity_check reported: {result}"),
                Some(session_id.to_owned()),
                None,
                None,
                vec![format!("integrity_check={result}")],
                "Treat the database as corrupt; preserve a copy and do not rely on its contents as trustworthy evidence.",
            ));
        }
        Err(err) => {
            findings.push(finding(
                "DB_INTEGRITY_CHECK_UNAVAILABLE",
                FindingSeverity::Critical,
                "SQLite integrity check could not be executed",
                format!("PRAGMA integrity_check failed: {err}"),
                Some(session_id.to_owned()),
                None,
                None,
                vec![],
                "Database integrity cannot be verified; treat results as unverifiable until the database can be inspected.",
            ));
            limitations.push("PRAGMA integrity_check could not be executed.".to_owned());
        }
    }

    match conn.prepare("PRAGMA foreign_key_check") {
        Ok(mut stmt) => match stmt.query([]) {
            Ok(mut rows) => {
                let mut violations = 0usize;
                while let Ok(Some(row)) = rows.next() {
                    violations += 1;
                    if violations <= 5 {
                        let table: String = row.get(0).unwrap_or_else(|_| "?".to_owned());
                        let rowid: i64 = row.get(1).unwrap_or(-1);
                        let parent: String = row.get(2).unwrap_or_else(|_| "?".to_owned());
                        let fkid: i64 = row.get(3).unwrap_or(-1);
                        findings.push(finding(
                            "DB_FOREIGN_KEY_VIOLATION",
                            FindingSeverity::Critical,
                            "Foreign-key integrity violation",
                            "A row references a missing parent record.",
                            Some(session_id.to_owned()),
                            None,
                            None,
                            vec![format!(
                                "table={table} rowid={rowid} parent={parent} fkid={fkid}"
                            )],
                            "Database relational integrity is broken; preserve evidence and investigate corruption/migration issues.",
                        ));
                    }
                }
                if violations > 5 {
                    findings.push(finding(
                        "DB_FOREIGN_KEY_VIOLATIONS_TRUNCATED",
                        FindingSeverity::Critical,
                        "Additional foreign-key violations omitted",
                        format!(
                            "{violations} foreign-key violations detected in total; only first 5 detailed."
                        ),
                        Some(session_id.to_owned()),
                        None,
                        None,
                        vec![format!("total_violations={violations}")],
                        "Database integrity is critically compromised; inspect all violations offline.",
                    ));
                }
            }
            Err(err) => {
                findings.push(finding(
                    "DB_FOREIGN_KEY_CHECK_FAILED",
                    FindingSeverity::Critical,
                    "Foreign-key check could not be executed",
                    format!("PRAGMA foreign_key_check failed: {err}"),
                    Some(session_id.to_owned()),
                    None,
                    None,
                    vec![],
                    "Relational integrity cannot be verified; treat database as unverifiable.",
                ));
                limitations.push("PRAGMA foreign_key_check failed.".to_owned());
            }
        },
        Err(err) => {
            findings.push(finding(
                "DB_FOREIGN_KEY_CHECK_FAILED",
                FindingSeverity::Critical,
                "Foreign-key check could not be prepared",
                format!("PRAGMA foreign_key_check prepare failed: {err}"),
                Some(session_id.to_owned()),
                None,
                None,
                vec![],
                "Relational integrity cannot be verified; treat database as unverifiable.",
            ));
            limitations.push("PRAGMA foreign_key_check could not be prepared.".to_owned());
        }
    }
}

fn run_schema_checks(
    conn: &Connection,
    session_id: &str,
    db_schema_version: u32,
    findings: &mut FindingSink,
    limitations: &mut Vec<String>,
) {
    if db_schema_version == 0 {
        findings.push(finding(
            "DB_SCHEMA_MISSING",
            FindingSeverity::Error,
            "Database schema is not initialized",
            "PRAGMA user_version is 0; required SYSCALL schema is missing.",
            Some(session_id.to_owned()),
            None,
            None,
            vec!["user_version=0".to_owned()],
            "Select a valid SYSCALL database or initialize it via a supported recording flow.",
        ));
        return;
    }
    if db_schema_version > LATEST_SCHEMA_VERSION {
        findings.push(finding(
            "DB_SCHEMA_UNSUPPORTED",
            FindingSeverity::Error,
            "Database schema version is unsupported by this build",
            format!(
                "Database schema v{db_schema_version} is newer than supported v{LATEST_SCHEMA_VERSION}."
            ),
            Some(session_id.to_owned()),
            None,
            None,
            vec![
                format!("db_schema_version={db_schema_version}"),
                format!("supported_max={LATEST_SCHEMA_VERSION}"),
            ],
            "Use a newer SYSCALL build to verify this database; do not assume semantic correctness.",
        ));
        limitations.push(
            "Schema is newer than this build supports; semantic checks may be incomplete."
                .to_owned(),
        );
        return;
    }

    for (table, required_cols) in [
        (
            "sessions",
            vec![
                "id",
                "schema_version",
                "started_at_ns",
                "status",
                "recording_scope",
            ],
        ),
        (
            "events",
            vec![
                "id",
                "session_id",
                "schema_version",
                "event_type",
                "timestamp_ns",
                "monotonic_ns",
                "process_instance_id",
                "payload",
            ],
        ),
    ] {
        match table_columns(conn, table) {
            Ok(Some(cols)) => {
                for col in required_cols {
                    if !cols.contains(col) {
                        findings.push(finding(
                            "DB_REQUIRED_COLUMN_MISSING",
                            FindingSeverity::Critical,
                            "Required database column is missing",
                            format!("Table '{table}' is missing required column '{col}'."),
                            Some(session_id.to_owned()),
                            None,
                            None,
                            vec![format!("table={table}"), format!("missing_column={col}")],
                            "Schema is inconsistent/corrupt for this build; treat verification as invalid.",
                        ));
                    }
                }
            }
            Ok(None) => {
                findings.push(finding(
                    "DB_REQUIRED_TABLE_MISSING",
                    FindingSeverity::Critical,
                    "Required database table is missing",
                    format!("Table '{table}' does not exist."),
                    Some(session_id.to_owned()),
                    None,
                    None,
                    vec![format!("table={table}")],
                    "Schema is incomplete/corrupt; treat database as invalid.",
                ));
            }
            Err(err) => {
                findings.push(finding(
                    "DB_SCHEMA_INSPECTION_FAILED",
                    FindingSeverity::Error,
                    "Schema inspection failed",
                    format!("Could not inspect table '{table}': {err}"),
                    Some(session_id.to_owned()),
                    None,
                    None,
                    vec![format!("table={table}")],
                    "Schema consistency cannot be fully verified.",
                ));
                limitations.push(format!("Could not inspect schema for table '{table}'."));
            }
        }
    }
}

fn read_session(
    conn: &Connection,
    id: &str,
) -> std::result::Result<Option<SessionSummary>, rusqlite::Error> {
    // Minimal read for verification; tolerate missing optional columns by selecting known core ones present in supported schemas.
    // We need enough fields for checks; use a broad select compatible with v3 (latest supported) and fall back if unavailable.
    let sql_v3 = "SELECT
            s.id, s.schema_version, s.started_at_ns, s.ended_at_ns, s.command,
            s.arguments, s.recording_scope, s.status, s.boot_id, s.kernel_release,
            s.collector_version, s.dropped_events, s.ringbuf_lost_events,
            s.userspace_dropped_events, s.malformed_events, s.filtered_events,
            s.error,
            s.termination_reason, s.target_exit_code, s.target_exit_signal,
            s.recovered_from_status, s.recovered_at_ns, s.finalized_at_ns,
            s.events_received, s.events_decoded, s.events_attributed,
            s.events_persisted, s.events_rejected_scope, s.events_rejected_malformed,
            s.events_persist_failed,
            (SELECT COUNT(*) FROM events e WHERE e.session_id = s.id),
            (SELECT COUNT(DISTINCT e.process_instance_id) FROM events e WHERE e.session_id = s.id)
        FROM sessions s WHERE s.id = ?1";
    let mut stmt = conn.prepare(sql_v3)?;
    let row = stmt.query_row(params![id], map_session_row_v3).optional()?;
    Ok(row)
}

fn map_session_row_v3(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionSummary> {
    let args_json: String = row.get(5)?;
    let arguments: Vec<String> = serde_json::from_str(&args_json).unwrap_or_default();
    let scope_str: String = row.get(6)?;
    let status_str: String = row.get(7)?;
    let rec_from: Option<String> = row.get(20)?;
    Ok(SessionSummary {
        id: row.get(0)?,
        schema_version: row.get::<_, i64>(1)? as u16,
        started_at_ns: row.get(2)?,
        ended_at_ns: row.get(3)?,
        command: row.get(4)?,
        arguments,
        recording_scope: scope_str
            .parse::<syscall_core::RecordingScope>()
            .unwrap_or(syscall_core::RecordingScope::TargetTree),
        status: SessionStatus::from_db(&status_str),
        boot_id: row.get(8)?,
        kernel_release: row.get(9)?,
        collector_version: row.get(10)?,
        dropped_events: row.get::<_, i64>(11)?.max(0) as u64,
        ringbuf_lost_events: row.get::<_, i64>(12)?.max(0) as u64,
        userspace_dropped_events: row.get::<_, i64>(13)?.max(0) as u64,
        malformed_events: row.get::<_, i64>(14)?.max(0) as u64,
        filtered_events: row.get::<_, i64>(15)?.max(0) as u64,
        error: row.get(16)?,
        termination_reason: row.get(17)?,
        target_exit_code: row.get(18)?,
        target_exit_signal: row.get(19)?,
        recovered_from_status: rec_from.as_deref().map(SessionStatus::from_db),
        recovered_at_ns: row.get(21)?,
        finalized_at_ns: row.get(22)?,
        events_received: row.get::<_, i64>(23).unwrap_or(0).max(0) as u64,
        events_decoded: row.get::<_, i64>(24).unwrap_or(0).max(0) as u64,
        events_attributed: row.get::<_, i64>(25).unwrap_or(0).max(0) as u64,
        events_persisted: row.get::<_, i64>(26).unwrap_or(0).max(0) as u64,
        events_rejected_scope: row.get::<_, i64>(27).unwrap_or(0).max(0) as u64,
        events_rejected_malformed: row.get::<_, i64>(28).unwrap_or(0).max(0) as u64,
        events_persist_failed: row.get::<_, i64>(29).unwrap_or(0).max(0) as u64,
        events_self_filtered: 0,
        event_count: row.get::<_, i64>(30).unwrap_or(0),
        process_count: row.get::<_, i64>(31).unwrap_or(0),
    })
}

fn check_session(session: &SessionSummary, findings: &mut FindingSink) {
    let sid = Some(session.id.clone());

    if session.status == SessionStatus::Unknown {
        findings.push(finding(
            "SESSION_STATUS_INVALID",
            FindingSeverity::Error,
            "Session status is invalid or unknown",
            "Session status value is not recognized by this build.",
            sid.clone(),
            None,
            None,
            vec![],
            "Treat session lifecycle metadata as untrustworthy and inspect raw database state.",
        ));
    }

    if session.started_at_ns <= 0 {
        findings.push(finding(
            "SESSION_TIMESTAMP_INVALID",
            FindingSeverity::Error,
            "Session start timestamp is invalid",
            "started_at_ns must be positive.",
            sid.clone(),
            None,
            None,
            vec![format!("started_at_ns={}", session.started_at_ns)],
            "Session timing metadata is inconsistent; interpret timestamps cautiously.",
        ));
    }
    if let Some(ended) = session.ended_at_ns {
        if ended < session.started_at_ns {
            findings.push(finding(
                "SESSION_TIMESTAMP_ORDER_INVALID",
                FindingSeverity::Error,
                "Session end precedes start",
                "ended_at_ns is earlier than started_at_ns.",
                sid.clone(),
                None,
                None,
                vec![format!(
                    "started_at_ns={} ended_at_ns={ended}",
                    session.started_at_ns
                )],
                "Session lifecycle timing is contradictory.",
            ));
        }
    }

    let terminal = session.status.is_terminal();
    let incomplete = matches!(
        session.status,
        SessionStatus::Starting | SessionStatus::Recording
    );

    if incomplete {
        findings.push(finding(
            "SESSION_INCOMPLETE",
            FindingSeverity::Warning,
            "Session is not in a terminal state",
            "Session status indicates recording may be incomplete or still in progress; evidence completeness cannot be assumed.",
            sid.clone(),
            None,
            None,
            vec![format!("status={}", session.status.as_str())],
            "Confirm whether recording is active; if not, treat evidence as incomplete and do not infer final outcome.",
        ));
        if session.ended_at_ns.is_some()
            || session.finalized_at_ns.is_some()
            || session.termination_reason.is_some()
            || session.target_exit_code.is_some()
            || session.target_exit_signal.is_some()
        {
            findings.push(finding(
                "SESSION_FINALIZATION_METADATA_INCONSISTENT",
                FindingSeverity::Error,
                "Non-terminal session has terminal/finalization metadata",
                "A starting/recording session should not have terminal outcome or finalization metadata.",
                sid.clone(),
                None,
                None,
                vec![],
                "Session lifecycle state contradicts recorded finalization metadata.",
            ));
        }
    }

    if terminal {
        if session.ended_at_ns.is_none() {
            findings.push(finding(
                "SESSION_FINALIZATION_METADATA_MISSING",
                FindingSeverity::Error,
                "Terminal session missing end timestamp",
                "A terminal session should record ended_at_ns.",
                sid.clone(),
                None,
                None,
                vec![format!("status={}", session.status.as_str())],
                "Lifecycle metadata is incomplete/contradictory; interpret outcome timing cautiously.",
            ));
        }
        if session.finalized_at_ns.is_none() && session.status == SessionStatus::Recovered {
            findings.push(finding(
                "SESSION_FINALIZATION_METADATA_INCONSISTENT",
                FindingSeverity::Error,
                "Recovered session missing finalization timestamp",
                "Recovered sessions should include finalized_at_ns/recovery metadata.",
                sid.clone(),
                None,
                None,
                vec![],
                "Recovery metadata is incomplete; verify recovery handling.",
            ));
        }
    }

    match session.status {
        SessionStatus::Recovered => {
            findings.push(finding(
                "SESSION_RECOVERED",
                FindingSeverity::Warning,
                "Session was recovered after abnormal termination",
                "The session ended in a non-terminal state previously and was recovered; committed events are preserved but the recording may be incomplete.",
                sid.clone(),
                None,
                None,
                vec![
                    format!(
                        "recovered_from_status={}",
                        session
                            .recovered_from_status
                            .map(|s| s.as_str())
                            .unwrap_or("unknown")
                    ),
                    format!(
                        "termination_reason={}",
                        session.termination_reason.as_deref().unwrap_or("unknown")
                    ),
                ],
                "Treat evidence as potentially incomplete and review recovery/termination context.",
            ));
            if session.recovered_from_status.is_none()
                || session.termination_reason.as_deref() != Some("abnormal_termination_recovered")
            {
                findings.push(finding(
                    "SESSION_RECOVERY_METADATA_INCONSISTENT",
                    FindingSeverity::Error,
                    "Recovered session has inconsistent recovery metadata",
                    "Recovered sessions should record prior non-terminal state and abnormal termination recovery reason.",
                    sid.clone(),
                    None,
                    None,
                    vec![],
                    "Recovery state is contradictory; inspect session metadata carefully.",
                ));
            }
            if session.recovered_at_ns.is_none() && session.finalized_at_ns.is_none() {
                findings.push(finding(
                    "SESSION_RECOVERY_METADATA_MISSING",
                    FindingSeverity::Warning,
                    "Recovered session missing recovery timestamps",
                    "Recovery timestamps were not recorded; this may limit reconstruction of recovery timing.",
                    sid.clone(),
                    None,
                    None,
                    vec![],
                    "Interpret recovery timing as unknown; rely on committed events/counters.",
                ));
            }
        }
        SessionStatus::Completed => {
            if session
                .termination_reason
                .as_deref()
                .is_some_and(|r| r.contains("abnormal") || r.contains("recovered"))
            {
                findings.push(finding(
                    "SESSION_TERMINATION_INCONSISTENT",
                    FindingSeverity::Error,
                    "Completed session claims abnormal termination",
                    "Termination reason contradicts completed status.",
                    sid.clone(),
                    None,
                    None,
                    vec![format!(
                        "termination_reason={}",
                        session.termination_reason.as_deref().unwrap_or("")
                    )],
                    "Session outcome metadata is contradictory.",
                ));
            }
        }
        SessionStatus::Interrupted
            if session.termination_reason.as_deref() == Some("target_exit") =>
        {
            findings.push(finding(
                "SESSION_TERMINATION_INCONSISTENT",
                FindingSeverity::Error,
                "Interrupted session claims normal target exit termination",
                "Interrupted sessions should not be reported as clean target completion.",
                sid.clone(),
                None,
                None,
                vec!["termination_reason=target_exit".to_owned()],
                "Lifecycle outcome is contradictory.",
            ));
        }
        _ => {}
    }

    // Loss/completeness counters (loss != corruption)
    let reported_dropped = session.dropped_events;
    let summed = session
        .ringbuf_lost_events
        .saturating_add(session.userspace_dropped_events)
        .saturating_add(session.malformed_events);
    if session.ringbuf_lost_events > 0 {
        findings.push(finding(
            "EVIDENCE_LOSS_RINGBUF",
            FindingSeverity::Warning,
            "Ring-buffer event loss reported",
            "Some events were lost before userspace delivery; the recorded trace may be incomplete.",
            sid.clone(),
            None,
            None,
            vec![format!(
                "ringbuf_lost_events={}",
                session.ringbuf_lost_events
            )],
            "Do not treat this as database corruption, but account for possible missing evidence.",
        ));
    }
    if session.userspace_dropped_events > 0 {
        findings.push(finding(
            "EVIDENCE_LOSS_USERSPACE",
            FindingSeverity::Warning,
            "Userspace event drops reported",
            "Some decoded/received events were dropped before persistence; the recorded trace may be incomplete.",
            sid.clone(),
            None,
            None,
            vec![format!(
                "userspace_dropped_events={}",
                session.userspace_dropped_events
            )],
            "Interpret absence of expected events cautiously.",
        ));
    }
    if reported_dropped != 0 && summed != 0 && reported_dropped < summed {
        findings.push(finding(
            "ACCOUNTING_INCONSISTENT",
            FindingSeverity::Warning,
            "Drop counters do not reconcile",
            "Aggregate dropped_events is less than the sum of specific drop/loss counters.",
            sid.clone(),
            None,
            None,
            vec![
                format!("dropped_events={reported_dropped}"),
                format!("sum_specific={summed}"),
            ],
            "Counter accounting may be incomplete; avoid strong quantitative claims.",
        ));
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct EventRow {
    id: i64,
    schema_version: i64,
    event_type: String,
    timestamp_ns: i64,
    monotonic_ns: i64,
    pid: i64,
    tid: i64,
    uid: Option<i64>,
    gid: Option<i64>,
    ppid: Option<i64>,
    process_instance_id: String,
    comm: String,
    payload: String,
    raw_bpf_pid: Option<i64>,
    raw_bpf_tgid: Option<i64>,
    observer_pid: Option<i64>,
    observer_tgid: Option<i64>,
    source_tracepoint: Option<String>,
    wire_schema_version: Option<i64>,
    attribution_method: Option<String>,
    timestamp_clock_domain: Option<String>,
    monotonic_clock_domain: Option<String>,
}

fn check_events_and_accounting(
    conn: &Connection,
    session: &SessionSummary,
    findings: &mut FindingSink,
    limitations: &mut Vec<String>,
    unable: &mut bool,
) {
    let sid = Some(session.id.clone());

    let actual_committed: i64 = match conn.query_row(
        "SELECT COUNT(*) FROM events WHERE session_id = ?1",
        params![session.id],
        |row| row.get(0),
    ) {
        Ok(v) => v,
        Err(err) => {
            findings.push(finding(
                "EVENT_COUNT_UNAVAILABLE",
                FindingSeverity::Error,
                "Committed event count could not be determined",
                format!("COUNT(*) on events failed: {err}"),
                sid.clone(),
                None,
                None,
                vec![],
                "Event-level and accounting verification is incomplete.",
            ));
            limitations.push("Could not count committed events.".to_owned());
            *unable = true;
            -1
        }
    };

    if actual_committed >= 0 {
        let actual_u = actual_committed.max(0) as u64;
        let accounting_counters_recorded = session.schema_version >= 2
            || session.events_persisted > 0
            || session.events_received > 0
            || session.events_decoded > 0
            || session.events_attributed > 0;
        if session.events_persisted != actual_u && session.status.is_terminal() {
            if accounting_counters_recorded {
                findings.push(finding(
                    "ACCOUNTING_PERSISTED_MISMATCH",
                    FindingSeverity::Error,
                    "Persisted event counter does not match committed rows",
                    "events_persisted differs from the actual committed event row count.",
                    sid.clone(),
                    None,
                    None,
                    vec![
                        format!("events_persisted={}", session.events_persisted),
                        format!("committed_rows={actual_u}"),
                    ],
                    "Accounting metadata is inconsistent; trust committed row count as the observable evidence set.",
                ));
            } else {
                findings.push(finding(
                    "ACCOUNTING_UNAVAILABLE_LEGACY",
                    FindingSeverity::Warning,
                    "Persisted-event accounting counter unavailable in legacy record",
                    "Historical session metadata does not record authoritative persisted-event accounting; committed row count is available.",
                    sid.clone(),
                    None,
                    None,
                    vec![
                        format!("events_persisted={}", session.events_persisted),
                        format!("committed_rows={actual_u}"),
                    ],
                    "Use committed event rows as observed evidence; do not treat missing legacy counters as corruption.",
                ));
            }
        }
        if session.event_count >= 0
            && session.event_count as u64 != actual_u
            && session.event_count != 0
            && actual_u != 0
        {
            findings.push(finding(
                "ACCOUNTING_DERIVED_COUNT_MISMATCH",
                FindingSeverity::Warning,
                "Derived session event count differs from committed rows",
                "Session summary event_count is inconsistent with committed events.",
                sid.clone(),
                None,
                None,
                vec![
                    format!("event_count={}", session.event_count),
                    format!("committed_rows={actual_u}"),
                ],
                "Treat derived counters as inconsistent and prefer direct event evidence.",
            ));
        }

        if session.status == SessionStatus::Recovered
            || session.ringbuf_lost_events > 0
            || session.userspace_dropped_events > 0
        {
            findings.push(finding(
                "ACCOUNTING_INCOMPLETE",
                FindingSeverity::Warning,
                "Event evidence may be incomplete",
                "Recovery or loss/drop counters indicate the persisted set may not represent all events that occurred.",
                sid.clone(),
                None,
                None,
                vec![
                    format!("status={}", session.status.as_str()),
                    format!("committed_rows={actual_u}"),
                    format!("events_received={}", session.events_received),
                    format!("events_decoded={}", session.events_decoded),
                    format!("events_attributed={}", session.events_attributed),
                    format!("events_persisted_reported={}", session.events_persisted),
                    format!("persist_failed={}", session.events_persist_failed),
                ],
                "Do not claim completeness; base conclusions only on committed evidence and reported limitations.",
            ));
        }
    }

    // Bounded, deterministic scan in persisted order.
    let mut stmt = match conn.prepare(
        "SELECT id, schema_version, event_type, timestamp_ns, monotonic_ns,
                pid, tid, uid, gid, ppid, process_instance_id, comm, payload,
                raw_bpf_pid, raw_bpf_tgid, observer_pid, observer_tgid,
                source_tracepoint, wire_schema_version, attribution_method,
                timestamp_clock_domain, monotonic_clock_domain
         FROM events
         WHERE session_id = ?1
         ORDER BY timestamp_ns ASC, monotonic_ns ASC, id ASC
         LIMIT ?2 OFFSET ?3",
    ) {
        Ok(s) => s,
        Err(err) => {
            findings.push(finding(
                "EVENT_SCAN_FAILED",
                FindingSeverity::Error,
                "Event evidence could not be scanned",
                format!("Preparing event scan failed: {err}"),
                sid.clone(),
                None,
                None,
                vec![],
                "Event-level integrity, ordering, and provenance checks are incomplete.",
            ));
            limitations.push("Event scan could not be prepared/executed.".to_owned());
            *unable = true;
            return;
        }
    };

    let mut offset: i64 = 0;
    let mut prev: Option<EventRow> = None;
    let mut seen_ids: HashSet<i64> = HashSet::new();
    let mut scanned: usize = 0;
    let mut provisional_or_unavailable_prov = 0usize;
    let mut legacy_prov = 0usize;
    let mut scan_error = false;

    loop {
        let rows = stmt.query_map(params![session.id, EVENT_PAGE_SIZE, offset], |row| {
            Ok(EventRow {
                id: row.get(0)?,
                schema_version: row.get(1)?,
                event_type: row.get(2)?,
                timestamp_ns: row.get(3)?,
                monotonic_ns: row.get(4)?,
                pid: row.get(5)?,
                tid: row.get(6)?,
                uid: row.get(7)?,
                gid: row.get(8)?,
                ppid: row.get(9)?,
                process_instance_id: row.get(10)?,
                comm: row.get(11)?,
                payload: row.get(12)?,
                raw_bpf_pid: row.get(13)?,
                raw_bpf_tgid: row.get(14)?,
                observer_pid: row.get(15)?,
                observer_tgid: row.get(16)?,
                source_tracepoint: row.get(17)?,
                wire_schema_version: row.get(18)?,
                attribution_method: row.get(19)?,
                timestamp_clock_domain: row.get(20)?,
                monotonic_clock_domain: row.get(21)?,
            })
        });
        let iter = match rows {
            Ok(i) => i,
            Err(err) => {
                findings.push(finding(
                    "EVENT_SCAN_FAILED",
                    FindingSeverity::Error,
                    "Event evidence scan failed",
                    format!("Querying events failed: {err}"),
                    sid.clone(),
                    None,
                    None,
                    vec![format!("offset={offset}")],
                    "Event-level checks could not be completed; treat verification as unable for full assurance.",
                ));
                *unable = true;
                scan_error = true;
                break;
            }
        };

        let mut page_count = 0i64;
        for row_res in iter {
            page_count += 1;
            let ev = match row_res {
                Ok(e) => e,
                Err(err) => {
                    findings.push(finding(
                        "EVENT_SCAN_FAILED",
                        FindingSeverity::Error,
                        "Event row could not be read",
                        format!("Reading event row failed: {err}"),
                        sid.clone(),
                        None,
                        None,
                        vec![format!("offset={offset}")],
                        "Event evidence may be corrupt or unreadable.",
                    ));
                    *unable = true;
                    scan_error = true;
                    break;
                }
            };
            scanned += 1;

            if !seen_ids.insert(ev.id) {
                findings.push(finding(
                    "EVENT_ID_DUPLICATE",
                    FindingSeverity::Critical,
                    "Duplicate event row identity observed in scan",
                    "The same event id was encountered more than once during deterministic ordered scan.",
                    sid.clone(),
                    Some(ev.id),
                    None,
                    vec![format!("event_id={}", ev.id)],
                    "This indicates corrupt/inconsistent scan results or storage corruption; verification cannot trust event identity.",
                ));
            }

            check_event_row(
                session,
                &ev,
                findings,
                &mut provisional_or_unavailable_prov,
                &mut legacy_prov,
            );

            if let Some(prev) = prev.as_ref() {
                // Deterministic ordering contract
                let ok = (prev.timestamp_ns, prev.monotonic_ns, prev.id)
                    <= (ev.timestamp_ns, ev.monotonic_ns, ev.id);
                if !ok {
                    findings.push(finding(
                        "EVENT_ORDER_INCONSISTENT",
                        FindingSeverity::Error,
                        "Event ordering/tie-breaker is inconsistent",
                        "Events are not in deterministic order (timestamp_ns, monotonic_ns, id).",
                        sid.clone(),
                        Some(ev.id),
                        None,
                        vec![
                            format!("prev_id={} prev_ts={} prev_mono={}", prev.id, prev.timestamp_ns, prev.monotonic_ns),
                            format!("curr_id={} curr_ts={} curr_mono={}", ev.id, ev.timestamp_ns, ev.monotonic_ns),
                        ],
                        "Ordering evidence is contradictory; do not rely on sequence reconstruction from this session.",
                    ));
                }
            }
            prev = Some(ev);
        }
        if scan_error {
            break;
        }
        if page_count < EVENT_PAGE_SIZE {
            break;
        }
        offset += page_count;
    }

    if legacy_prov > 0 {
        findings.push(finding(
            "PROVENANCE_UNAVAILABLE_LEGACY",
            FindingSeverity::Warning,
            "Legacy/unavailable provenance fields observed",
            "Some events lack provenance details (expected for legacy or pre-provenance records). This is not by itself corruption.",
            sid.clone(),
            None,
            None,
            vec![format!("events_with_unavailable_provenance={legacy_prov}")],
            "Interpret provenance/attribution as unavailable where missing; do not fabricate historical values.",
        ));
    }
    if provisional_or_unavailable_prov > 0 && legacy_prov == 0 {
        findings.push(finding(
            "PROVENANCE_UNAVAILABLE",
            FindingSeverity::Warning,
            "Some event provenance/attribution is unavailable or provisional",
            "One or more events do not provide fully resolved provenance/observer attribution evidence.",
            sid.clone(),
            None,
            None,
            vec![format!("events_with_unavailable_or_provisional_provenance={provisional_or_unavailable_prov}")],
            "Treat affected events as having limited attribution certainty; do not assume canonical observer identity where unavailable.",
        ));
    }
    if !scan_error && actual_committed >= 0 && scanned as i64 != actual_committed {
        findings.push(finding(
            "EVENT_SCAN_INCOMPLETE",
            FindingSeverity::Error,
            "Event scan count differs from committed row count",
            "Deterministic scan did not observe the same number of rows as COUNT(*).",
            sid.clone(),
            None,
            None,
            vec![
                format!("scanned={scanned}"),
                format!("committed_rows={actual_committed}"),
            ],
            "Event evidence is inconsistent or unreadable; verification cannot be considered complete.",
        ));
        *unable = true;
    }

    // Fork-specific unresolved identity note (bounded): if any fork event had provisional attribution or missing observer fields, call it out.
    // (Detailed per-event findings emitted in check_event_row.)
    let _ = limitations; // limitations used by callers; no extra global limitation here.
}

fn check_activity_semantics(
    session: &SessionSummary,
    ev: &EventRow,
    event_type: EventType,
    payload: EventPayload,
    findings: &mut FindingSink,
) {
    let sid = Some(session.id.clone());
    let eid = Some(ev.id);
    let mut emit = |code: &str, severity, title: &str, detail: String, evidence: Vec<String>| {
        findings.push(finding(
            code,
            severity,
            title,
            detail,
            sid.clone(),
            eid,
            Some(ev.process_instance_id.clone()),
            evidence,
            "Activity evidence is internally contradictory; do not rely on the affected field.",
        ));
    };

    match (event_type, payload) {
        (
            EventType::FileOpen,
            EventPayload::FileOpen {
                path,
                result,
                success,
                errno,
                path_truncated,
                ..
            },
        ) => {
            if ev
                .source_tracepoint
                .as_deref()
                .is_some_and(|source| source != "syscalls/sys_exit_openat")
            {
                emit(
                    "EVENT_FILE_TRACEPOINT_INCONSISTENT",
                    FindingSeverity::Error,
                    "File-open event has an inconsistent source tracepoint",
                    "file_open events must originate from syscalls/sys_exit_openat.".to_owned(),
                    vec![format!(
                        "source_tracepoint={}",
                        ev.source_tracepoint.as_deref().unwrap_or("unknown")
                    )],
                );
            }
            if ev.wire_schema_version.is_some_and(|version| version < 3) {
                emit(
                    "EVENT_ACTIVITY_WIRE_SCHEMA_INCONSISTENT",
                    FindingSeverity::Error,
                    "Activity event has an incompatible wire schema version",
                    "file_open events require wire schema >= 3.".to_owned(),
                    vec![format!(
                        "wire_schema_version={}",
                        ev.wire_schema_version.unwrap_or_default()
                    )],
                );
            }
            validate_activity_result("file_open", result, success, errno, true, &mut emit);
            if path.len() > syscall_core::MAX_FILENAME_LEN || path.as_bytes().contains(&0) {
                emit(
                    "EVENT_FILE_PATH_INVALID",
                    FindingSeverity::Error,
                    "File-open path is invalid",
                    "Recorded path exceeds the schema limit or contains a NUL byte.".to_owned(),
                    vec![format!("path_len={}", path.len())],
                );
            }
            if path_truncated && path.len() < syscall_core::MAX_FILENAME_LEN - 1 {
                emit(
                    "EVENT_FILE_TRUNCATION_INCONSISTENT",
                    FindingSeverity::Warning,
                    "File-open path is marked truncated but short",
                    "The path is marked truncated but is shorter than the capture limit; truncation metadata may be inconsistent.".to_owned(),
                    vec![format!("path_len={}", path.len())],
                );
            }
        }
        (
            EventType::NetworkConnect,
            EventPayload::NetworkConnect {
                family,
                source_address,
                source_port,
                destination_address,
                destination_port,
                result,
                success,
                errno,
                established,
            },
        ) => {
            if ev
                .source_tracepoint
                .as_deref()
                .is_some_and(|source| source != "syscalls/sys_exit_connect")
            {
                emit(
                    "EVENT_NETWORK_TRACEPOINT_INCONSISTENT",
                    FindingSeverity::Error,
                    "Network event has an inconsistent source tracepoint",
                    "network_connect events must originate from syscalls/sys_exit_connect."
                        .to_owned(),
                    vec![format!(
                        "source_tracepoint={}",
                        ev.source_tracepoint.as_deref().unwrap_or("unknown")
                    )],
                );
            }
            if ev.wire_schema_version.is_some_and(|version| version < 3) {
                emit(
                    "EVENT_ACTIVITY_WIRE_SCHEMA_INCONSISTENT",
                    FindingSeverity::Error,
                    "Activity event has an incompatible wire schema version",
                    "network_connect events require wire schema >= 3.".to_owned(),
                    vec![format!(
                        "wire_schema_version={}",
                        ev.wire_schema_version.unwrap_or_default()
                    )],
                );
            }
            validate_activity_result("network_connect", result, success, errno, false, &mut emit);
            if established {
                emit(
                    "EVENT_NETWORK_ESTABLISHED_CLAIM",
                    FindingSeverity::Error,
                    "Network event claims an established connection",
                    "The syscall tracepoint records connect attempts, not established connections."
                        .to_owned(),
                    vec!["established=true".to_owned()],
                );
            }
            if !valid_address(family, &destination_address) {
                emit(
                    "EVENT_NETWORK_ADDRESS_INVALID",
                    FindingSeverity::Error,
                    "Network destination address does not match its family",
                    "The stored address is not a valid address for the declared family.".to_owned(),
                    vec![format!("family={family} address={destination_address}")],
                );
            }
            match (source_address, source_port) {
                (Some(address), Some(_)) => {
                    if !valid_address(family, &address) {
                        emit(
                            "EVENT_NETWORK_ADDRESS_INVALID",
                            FindingSeverity::Error,
                            "Network source address does not match its family",
                            "The stored source address is not valid for the declared family."
                                .to_owned(),
                            vec![format!("family={family} address={address}")],
                        );
                    }
                }
                (None, None) => {}
                _ => emit(
                    "EVENT_NETWORK_SOURCE_INCONSISTENT",
                    FindingSeverity::Error,
                    "Network source address and port are inconsistent",
                    "Source address and source port must both be present or both be absent."
                        .to_owned(),
                    vec![],
                ),
            }
            if destination_port == 0 {
                emit(
                    "EVENT_NETWORK_PORT_INVALID",
                    FindingSeverity::Warning,
                    "Network destination port is zero",
                    "Port 0 is not a usable destination port for a recorded connect attempt."
                        .to_owned(),
                    vec!["destination_port=0".to_owned()],
                );
            }
            if source_port.is_some_and(|port| port == 0) {
                emit(
                    "EVENT_NETWORK_PORT_INVALID",
                    FindingSeverity::Warning,
                    "Network source port is zero",
                    "A recorded source port of zero has limited evidential value.".to_owned(),
                    vec!["source_port=0".to_owned()],
                );
            }
        }
        (EventType::FileOpen | EventType::NetworkConnect, other) => {
            emit(
                "EVENT_PAYLOAD_TYPE_MISMATCH",
                FindingSeverity::Error,
                "Activity event payload does not match its event type",
                format!(
                    "Event type {event_type} carries payload kind {}.",
                    other.event_type().as_str()
                ),
                vec![],
            );
        }
        _ => {}
    }
}

fn validate_activity_result<F>(
    kind: &str,
    result: i64,
    success: bool,
    errno: Option<i32>,
    non_negative_is_success: bool,
    finding: &mut F,
) where
    F: FnMut(&str, FindingSeverity, &str, String, Vec<String>),
{
    let expected_success = if non_negative_is_success {
        result >= 0
    } else {
        result == 0
    };
    if success != expected_success {
        finding(
            "EVENT_ACTIVITY_RESULT_INCONSISTENT",
            FindingSeverity::Error,
            "Activity success flag disagrees with the raw result",
            format!("{kind} records success={success} with result={result}."),
            vec![format!("result={result}")],
        );
    }
    if success {
        if errno.is_some() {
            finding(
                "EVENT_ACTIVITY_ERRNO_INCONSISTENT",
                FindingSeverity::Error,
                "Successful activity event carries an errno",
                format!("{kind} records success with errno={errno:?}."),
                vec![],
            );
        }
        return;
    }
    let expected_errno = result
        .checked_neg()
        .filter(|value| *value > 0 && *value <= i64::from(i32::MAX));
    if expected_errno != errno.map(i64::from) {
        finding(
            "EVENT_ACTIVITY_ERRNO_INCONSISTENT",
            FindingSeverity::Error,
            "Activity errno does not match the raw result",
            format!("{kind} stores errno={errno:?} with result={result}."),
            vec![format!("result={result}")],
        );
    }
}

fn valid_address(family: AddressFamily, value: &str) -> bool {
    match family {
        AddressFamily::Ipv4 => value.parse::<std::net::Ipv4Addr>().is_ok(),
        AddressFamily::Ipv6 => value.parse::<std::net::Ipv6Addr>().is_ok(),
    }
}

fn check_event_row(
    session: &SessionSummary,
    ev: &EventRow,
    findings: &mut FindingSink,
    provisional_or_unavailable_prov: &mut usize,
    legacy_prov: &mut usize,
) {
    let sid = Some(session.id.clone());
    let eid = Some(ev.id);

    if ev.timestamp_ns <= 0 || ev.monotonic_ns < 0 {
        findings.push(finding(
            "EVENT_TIMESTAMP_INVALID",
            FindingSeverity::Error,
            "Event timestamp is invalid",
            "Event contains non-positive wall timestamp or negative monotonic timestamp.",
            sid.clone(),
            eid,
            Some(ev.process_instance_id.clone()),
            vec![
                format!("timestamp_ns={}", ev.timestamp_ns),
                format!("monotonic_ns={}", ev.monotonic_ns),
            ],
            "Event timing evidence is invalid/corrupt.",
        ));
    }

    let etype = ev.event_type.parse::<EventType>().ok();
    if etype.is_none() {
        findings.push(finding(
            "EVENT_TYPE_INVALID",
            FindingSeverity::Error,
            "Event type is invalid or unknown",
            "Stored event_type is not recognized.",
            sid.clone(),
            eid,
            Some(ev.process_instance_id.clone()),
            vec![format!("event_type={}", ev.event_type)],
            "Event semantics cannot be interpreted safely.",
        ));
    }

    // Basic payload JSON validity (do not leak payload content).
    if serde_json::from_str::<serde_json::Value>(&ev.payload).is_err() {
        findings.push(finding(
            "EVENT_PAYLOAD_INVALID",
            FindingSeverity::Error,
            "Event payload is not valid JSON",
            "Stored event payload could not be parsed as JSON.",
            sid.clone(),
            eid,
            Some(ev.process_instance_id.clone()),
            vec![format!("payload_len={}", ev.payload.len())],
            "Event payload evidence is corrupt or unreadable.",
        ));
    }

    if let (Some(event_type), Ok(payload)) =
        (etype, serde_json::from_str::<EventPayload>(&ev.payload))
    {
        check_activity_semantics(session, ev, event_type, payload, findings);
    }

    // Identity sanity (distinguish missing/unresolved/provisional/contradictory).
    if ev.process_instance_id.trim().is_empty() {
        findings.push(finding(
            "EVENT_IDENTITY_INVALID",
            FindingSeverity::Error,
            "Event process identity is missing",
            "process_instance_id is empty; event cannot be attributed to a process instance.",
            sid.clone(),
            eid,
            None,
            vec![],
            "Identity evidence is invalid/corrupt.",
        ));
    } else if ev.pid > 0 {
        // If instance encodes pid (best-effort), require consistency.
        let parts: Vec<&str> = ev.process_instance_id.split(':').collect();
        if parts.len() >= 2 {
            if let Ok(inst_pid) = parts[1].parse::<i64>() {
                if inst_pid != ev.pid {
                    findings.push(finding(
                        "EVENT_PROCESS_INSTANCE_INCONSISTENT",
                        FindingSeverity::Error,
                        "Event canonical PID contradicts process_instance_id",
                        "Canonical pid field and encoded process instance identity disagree.",
                        sid.clone(),
                        eid,
                        Some(ev.process_instance_id.clone()),
                        vec![
                            format!("pid={}", ev.pid),
                            format!("instance_pid={inst_pid}"),
                        ],
                        "Process identity evidence is contradictory.",
                    ));
                }
            }
        }
    }
    if ev.pid <= 0 || ev.tid <= 0 {
        findings.push(finding(
            "EVENT_IDENTITY_INVALID",
            FindingSeverity::Error,
            "Event PID/TID identity is invalid",
            "Canonical pid/tid must be positive.",
            sid.clone(),
            eid,
            Some(ev.process_instance_id.clone()),
            vec![format!("pid={} tid={}", ev.pid, ev.tid)],
            "Identity evidence is invalid/corrupt.",
        ));
    }

    // Raw/observer IDs: missing/unresolved is not corruption; non-positive present values are contradictory.
    for (name, val) in [
        ("raw_bpf_pid", ev.raw_bpf_pid),
        ("raw_bpf_tgid", ev.raw_bpf_tgid),
        ("observer_pid", ev.observer_pid),
        ("observer_tgid", ev.observer_tgid),
    ] {
        if let Some(v) = val {
            if v <= 0 {
                findings.push(finding(
                    "EVENT_PROVENANCE_INVALID",
                    FindingSeverity::Error,
                    "Provenance identity field is invalid",
                    format!("{name} is present but not positive."),
                    sid.clone(),
                    eid,
                    Some(ev.process_instance_id.clone()),
                    vec![format!("{name}={v}")],
                    "Provenance evidence is contradictory/corrupt.",
                ));
            }
        }
    }

    // Attribution semantics (distinguish missing/unresolved/provisional/contradictory).
    let method = ev.attribution_method.as_deref();
    let has_any_prov = ev.raw_bpf_pid.is_some()
        || ev.raw_bpf_tgid.is_some()
        || ev.observer_pid.is_some()
        || ev.observer_tgid.is_some()
        || ev.source_tracepoint.is_some()
        || ev.wire_schema_version.is_some()
        || ev.attribution_method.is_some();

    if !has_any_prov {
        // Legacy/unavailable: expected for historical records.
        *legacy_prov += 1;
    } else {
        let correlated = matches!(
            method,
            Some("ns_tgid_correlated") | Some("correlated") | Some("ns_tgid")
        );
        let provisional = matches!(
            method,
            Some("provisional_raw")
                | Some("provisional")
                | Some("unresolved")
                | Some("unresolved_fork")
                | Some("observer_unavailable")
        );
        if correlated {
            if ev.observer_pid.is_none() || ev.observer_tgid.is_none() {
                findings.push(finding(
                    "EVENT_PROVENANCE_INCONSISTENT",
                    FindingSeverity::Error,
                    "Correlated attribution missing observer identity",
                    "Attribution method claims correlated observer identity but observer_pid/tgid are unavailable.",
                    sid.clone(),
                    eid,
                    Some(ev.process_instance_id.clone()),
                    vec![format!("attribution_method={}", method.unwrap_or("unknown"))],
                    "Attribution evidence is contradictory; observer identity cannot be trusted.",
                ));
            }
            if ev.raw_bpf_tgid == Some(0) {
                // only provisional/unresolved cases may carry raw ns tgid 0; correlated should not
                findings.push(finding(
                    "EVENT_PROVENANCE_INCONSISTENT",
                    FindingSeverity::Error,
                    "Correlated attribution has unresolved raw TGID",
                    "Correlated attribution reported raw_bpf_tgid=0, which indicates unresolved identity.",
                    sid.clone(),
                    eid,
                    Some(ev.process_instance_id.clone()),
                    vec!["raw_bpf_tgid=0".to_owned()],
                    "Attribution evidence is contradictory.",
                ));
            }
        } else if provisional || method.is_none() {
            *provisional_or_unavailable_prov += 1;
            if matches!(etype, Some(EventType::ProcessFork)) && ev.observer_pid.is_none() {
                findings.push(finding(
                    "FORK_IDENTITY_UNRESOLVED",
                    FindingSeverity::Warning,
                    "Fork event identity/provenance is unresolved or provisional",
                    "Fork event lacks fully resolved observer attribution; this may be expected but limits identity certainty.",
                    sid.clone(),
                    eid,
                    Some(ev.process_instance_id.clone()),
                    vec![format!(
                        "attribution_method={}",
                        method.unwrap_or("unavailable")
                    )],
                    "Treat fork attribution as unresolved/provisional; do not assume fabricated canonical identities beyond recorded evidence.",
                ));
            }
        }
    }

    // Wire schema / tracepoint contract (defensible checks only).
    if let Some(ws) = ev.wire_schema_version {
        if !(1..=16).contains(&ws) {
            findings.push(finding(
                "EVENT_WIRE_SCHEMA_INVALID",
                FindingSeverity::Error,
                "Event wire schema version is invalid",
                "Recorded wire_schema_version is outside the recognized collected range.",
                sid.clone(),
                eid,
                Some(ev.process_instance_id.clone()),
                vec![format!("wire_schema_version={ws}")],
                "Provenance of event encoding is untrusted/invalid.",
            ));
        }
    }
    if let (Some(tp), Some(et)) = (ev.source_tracepoint.as_deref(), etype) {
        let ok = matches!(
            (tp, et),
            ("sched/sched_process_exec", EventType::ProcessExec)
                | ("sched/sched_process_fork", EventType::ProcessFork)
                | ("sched/sched_process_exit", EventType::ProcessExit)
                | ("syscalls/sys_exit_openat", EventType::FileOpen)
                | ("syscalls/sys_exit_connect", EventType::NetworkConnect)
        );
        if !ok {
            findings.push(finding(
                "EVENT_SOURCE_TRACEPOINT_INCONSISTENT",
                FindingSeverity::Error,
                "Event source tracepoint contradicts event type",
                "Recorded source tracepoint does not match the stored event type.",
                sid.clone(),
                eid,
                Some(ev.process_instance_id.clone()),
                vec![
                    format!("source_tracepoint={tp}"),
                    format!("event_type={}", et.as_str()),
                ],
                "Event provenance/type evidence is contradictory.",
            ));
        }
    }

    // session schema hint: if session is legacy and event schema older, provenance absence expected
    if session.schema_version < 3 && !has_any_prov {
        // already counted as legacy_prov; no extra contradictory finding
    }
}

#[allow(clippy::too_many_arguments)]
fn finding(
    code: &str,
    severity: FindingSeverity,
    title: impl Into<String>,
    detail: impl Into<String>,
    session_id: Option<String>,
    event_id: Option<i64>,
    process_instance_id: Option<String>,
    evidence: Vec<String>,
    recommendation: impl Into<String>,
) -> VerificationFinding {
    VerificationFinding {
        code: code.to_owned(),
        severity,
        title: title.into(),
        detail: detail.into(),
        session_id,
        event_id,
        process_instance_id,
        evidence,
        recommendation: recommendation.into(),
    }
}

fn read_user_version(conn: &Connection) -> std::result::Result<u32, rusqlite::Error> {
    conn.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
}

fn table_columns(
    conn: &Connection,
    table: &str,
) -> std::result::Result<Option<HashSet<String>>, rusqlite::Error> {
    let mut stmt = match conn.prepare(&format!("PRAGMA table_info({table})")) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    let mut rows = stmt.query([])?;
    let mut cols = HashSet::new();
    let mut any = false;
    while let Some(row) = rows.next()? {
        any = true;
        let name: String = row.get(1)?;
        cols.insert(name);
    }
    if any {
        Ok(Some(cols))
    } else {
        // Could be missing table or empty; distinguish by sqlite_master
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |r| r.get(0),
            )
            .optional()?;
        if exists.is_some() {
            Ok(Some(cols))
        } else {
            Ok(None)
        }
    }
}
