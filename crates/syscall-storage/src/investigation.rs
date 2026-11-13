//! Read-only investigation queries over persisted session evidence.
//!
//! All queries are bounded and use deterministic ordering. Results are derived
//! only from recorded evidence; missing or unresolved relationships are reported
//! explicitly and never invented.

use std::collections::{BTreeMap, HashMap};

use rusqlite::params;
use serde::{Deserialize, Serialize};
use syscall_core::{AddressFamily, Event, EventPayload, EventType};

use crate::db::Storage;
use crate::error::{Result, StorageError};

/// Filters for timeline/event investigation queries.
#[derive(Debug, Clone, Default)]
pub struct TimelineFilter {
    pub session_id: String,
    pub limit: Option<usize>,
    pub offset: usize,
    pub event_type: Option<EventType>,
    pub pid: Option<i32>,
    pub process_instance_id: Option<String>,
    /// Inclusive lower bound on event wall-clock timestamp (ns).
    pub from_ns: Option<i64>,
    /// Inclusive upper bound on event wall-clock timestamp (ns).
    pub to_ns: Option<i64>,
    /// Case-insensitive literal substring matched against comm, process
    /// instance, and persisted payload JSON. Applied in SQL.
    pub search: Option<String>,
}

impl TimelineFilter {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            limit: None,
            offset: 0,
            event_type: None,
            pid: None,
            process_instance_id: None,
            from_ns: None,
            to_ns: None,
            search: None,
        }
    }
}

/// Filters for filesystem/network activity queries. Filters operate on the
/// recorded payload fields and are applied in SQL so pagination stays
/// deterministic and bounded.
#[derive(Debug, Clone, Default)]
pub struct ActivityFilter {
    pub session_id: String,
    pub limit: Option<usize>,
    pub offset: usize,
    pub pid: Option<i32>,
    pub process_instance_id: Option<String>,
    pub from_ns: Option<i64>,
    pub to_ns: Option<i64>,
    /// `Some(true)` = successful attempts, `Some(false)` = failed attempts.
    pub success: Option<bool>,
    /// Only for network connections.
    pub family: Option<AddressFamily>,
    /// Case-insensitive literal substring matched against path/address,
    /// comm, and process instance. Applied in SQL.
    pub search: Option<String>,
}

impl ActivityFilter {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            limit: None,
            offset: 0,
            pid: None,
            process_instance_id: None,
            from_ns: None,
            to_ns: None,
            success: None,
            family: None,
            search: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileActivity {
    pub event_id: i64,
    pub timestamp_ns: i64,
    pub pid: i32,
    pub process_instance_id: String,
    pub comm: String,
    pub path: String,
    pub path_is_absolute: bool,
    pub path_truncated: bool,
    pub dirfd: i32,
    pub flags: u32,
    pub result: i64,
    pub success: bool,
    pub errno: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionActivity {
    pub event_id: i64,
    pub timestamp_ns: i64,
    pub pid: i32,
    pub process_instance_id: String,
    pub comm: String,
    pub family: AddressFamily,
    pub source_address: Option<String>,
    pub source_port: Option<u16>,
    pub destination_address: String,
    pub destination_port: u16,
    pub result: i64,
    pub success: bool,
    pub errno: Option<i32>,
    pub established: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInstanceEvidence {
    pub process_instance_id: String,
    pub pid: i32,
    pub comm: String,
    /// Executable filename observed in exec payloads for this instance, if any.
    pub executable: Option<String>,
    /// Command line is not recorded per-process in Mission 01 payloads; target
    /// command is session-level. Present only when session-level target matches
    /// this instance and arguments are available (respecting redaction).
    pub command_line: Option<String>,
    pub first_seen_ns: i64,
    pub last_seen_ns: i64,
    pub event_count: u64,
    /// True when a process_exit event was observed for this instance.
    pub exit_observed: bool,
    /// Exit priority from observed exit payload, if any (not a POSIX exit code).
    pub exit_priority: Option<i32>,
    /// Derived parent pid from observed fork/exec evidence for this instance.
    pub parent_pid: Option<i32>,
    /// Derived parent process instance id when confidently established from evidence.
    pub parent_process_instance_id: Option<String>,
    /// True when identity/ancestry evidence is incomplete or unresolved.
    pub identity_unresolved: bool,
    pub ancestry_unresolved: bool,
    /// Human-readable notes explaining unresolved/limited evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionStats {
    pub session_id: String,
    pub status: String,
    pub started_at_ns: i64,
    pub ended_at_ns: Option<i64>,
    pub duration_ns: Option<i64>,
    pub process_count: i64,
    pub event_count: i64,
    pub events_persisted: u64,
    pub events_by_type: BTreeMap<String, u64>,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub dropped_events_total: u64,
    pub malformed_events: u64,
    pub filtered_events: u64,
    pub events_rejected_scope: u64,
    pub events_rejected_malformed: u64,
    pub events_persist_failed: u64,
    pub events_self_filtered: u64,
    pub unresolved_identity_count: u64,
    pub termination_reason: Option<String>,
    pub target_exit_code: Option<i32>,
    pub target_exit_signal: Option<i32>,
    /// Evidence completeness: true when losses/rejections/unresolved evidence indicate
    /// observed counts may not represent all activity.
    pub evidence_may_be_incomplete: bool,
}

impl Storage {
    /// Fetch one persisted event by database row id, constrained to a session.
    /// Returning `None` for a mismatched session prevents cross-session access.
    pub fn get_event(&self, session_id: &str, event_id: i64) -> Result<Option<Event>> {
        let mut stmt = self.connection().prepare(
            "SELECT id, session_id, schema_version, event_type, timestamp_ns,
                    monotonic_ns, pid, tid, ppid, uid, gid, process_instance_id,
                    comm, payload,
                    raw_bpf_pid, raw_bpf_tgid, observer_pid, observer_tgid,
                    source_tracepoint, wire_schema_version, attribution_method,
                    timestamp_clock_domain, monotonic_clock_domain
             FROM events WHERE session_id = ?1 AND id = ?2",
        )?;
        match stmt.query_row(params![session_id, event_id], crate::db::row_to_event) {
            Ok(event) => Ok(Some(event)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(StorageError::from(err)),
        }
    }

    /// Query recorded file-open attempts in deterministic order.
    pub fn query_file_activity(&self, filter: &ActivityFilter) -> Result<Vec<FileActivity>> {
        let limit = filter
            .limit
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX))
            .unwrap_or(i64::MAX);
        let offset = i64::try_from(filter.offset).unwrap_or(i64::MAX);
        let success = filter.success.map(|value| if value { 1i64 } else { 0 });
        let mut stmt = self.connection().prepare(
            "SELECT id, timestamp_ns, pid, process_instance_id, comm, payload
             FROM events
             WHERE session_id = ?1 AND event_type = 'file_open'
               AND (?2 IS NULL OR pid = ?2)
               AND (?3 IS NULL OR process_instance_id = ?3)
               AND (?4 IS NULL OR timestamp_ns >= ?4)
               AND (?5 IS NULL OR timestamp_ns <= ?5)
               AND (?6 IS NULL OR (json_valid(payload) AND json_extract(payload, '$.success') = ?6))
               AND (?9 IS NULL OR instr(lower(comm), lower(?9)) > 0
                    OR instr(lower(process_instance_id), lower(?9)) > 0
                    OR instr(lower(payload), lower(?9)) > 0)
             ORDER BY timestamp_ns ASC, monotonic_ns ASC, id ASC
             LIMIT ?7 OFFSET ?8",
        )?;
        let rows = stmt.query_map(
            params![
                filter.session_id,
                filter.pid,
                filter.process_instance_id,
                filter.from_ns,
                filter.to_ns,
                success,
                limit,
                offset,
                filter.search,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (event_id, timestamp_ns, pid, process_instance_id, comm, payload) = row?;
            let payload = parse_file_payload(&payload)?;
            out.push(FileActivity {
                event_id,
                timestamp_ns,
                pid: i32::try_from(pid).unwrap_or(0),
                process_instance_id,
                comm,
                path: payload.0,
                path_is_absolute: payload.1,
                path_truncated: payload.2,
                dirfd: payload.3,
                flags: payload.4,
                result: payload.5,
                success: payload.6,
                errno: payload.7,
            });
        }
        Ok(out)
    }

    pub fn count_file_activity(&self, filter: &ActivityFilter) -> Result<u64> {
        let success = filter.success.map(|value| if value { 1i64 } else { 0 });
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM events
             WHERE session_id = ?1 AND event_type = 'file_open'
               AND (?2 IS NULL OR pid = ?2)
               AND (?3 IS NULL OR process_instance_id = ?3)
               AND (?4 IS NULL OR timestamp_ns >= ?4)
               AND (?5 IS NULL OR timestamp_ns <= ?5)
               AND (?6 IS NULL OR (json_valid(payload) AND json_extract(payload, '$.success') = ?6))
               AND (?7 IS NULL OR instr(lower(comm), lower(?7)) > 0
                    OR instr(lower(process_instance_id), lower(?7)) > 0
                    OR instr(lower(payload), lower(?7)) > 0)",
            params![
                filter.session_id,
                filter.pid,
                filter.process_instance_id,
                filter.from_ns,
                filter.to_ns,
                success,
                filter.search,
            ],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Query recorded IPv4/IPv6 connect attempts in deterministic order.
    pub fn query_connection_activity(
        &self,
        filter: &ActivityFilter,
    ) -> Result<Vec<ConnectionActivity>> {
        let limit = filter
            .limit
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX))
            .unwrap_or(i64::MAX);
        let offset = i64::try_from(filter.offset).unwrap_or(i64::MAX);
        let success = filter.success.map(|value| if value { 1i64 } else { 0 });
        let family = filter.family.map(|value| value.as_str());
        let mut stmt = self.connection().prepare(
            "SELECT id, timestamp_ns, pid, process_instance_id, comm, payload
             FROM events
             WHERE session_id = ?1 AND event_type = 'network_connect'
               AND (?2 IS NULL OR pid = ?2)
               AND (?3 IS NULL OR process_instance_id = ?3)
               AND (?4 IS NULL OR timestamp_ns >= ?4)
               AND (?5 IS NULL OR timestamp_ns <= ?5)
               AND (?6 IS NULL OR (json_valid(payload) AND json_extract(payload, '$.family') = ?6))
               AND (?7 IS NULL OR (json_valid(payload) AND json_extract(payload, '$.success') = ?7))
               AND (?10 IS NULL OR instr(lower(comm), lower(?10)) > 0
                    OR instr(lower(process_instance_id), lower(?10)) > 0
                    OR instr(lower(payload), lower(?10)) > 0)
             ORDER BY timestamp_ns ASC, monotonic_ns ASC, id ASC
             LIMIT ?8 OFFSET ?9",
        )?;
        let rows = stmt.query_map(
            params![
                filter.session_id,
                filter.pid,
                filter.process_instance_id,
                filter.from_ns,
                filter.to_ns,
                family,
                success,
                limit,
                offset,
                filter.search,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (event_id, timestamp_ns, pid, process_instance_id, comm, payload) = row?;
            let payload = parse_connection_payload(&payload)?;
            out.push(ConnectionActivity {
                event_id,
                timestamp_ns,
                pid: i32::try_from(pid).unwrap_or(0),
                process_instance_id,
                comm,
                family: payload.0,
                source_address: payload.1,
                source_port: payload.2,
                destination_address: payload.3,
                destination_port: payload.4,
                result: payload.5,
                success: payload.6,
                errno: payload.7,
                established: payload.8,
            });
        }
        Ok(out)
    }

    pub fn count_connection_activity(&self, filter: &ActivityFilter) -> Result<u64> {
        let success = filter.success.map(|value| if value { 1i64 } else { 0 });
        let family = filter.family.map(|value| value.as_str());
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM events
             WHERE session_id = ?1 AND event_type = 'network_connect'
               AND (?2 IS NULL OR pid = ?2)
               AND (?3 IS NULL OR process_instance_id = ?3)
               AND (?4 IS NULL OR timestamp_ns >= ?4)
               AND (?5 IS NULL OR timestamp_ns <= ?5)
               AND (?6 IS NULL OR (json_valid(payload) AND json_extract(payload, '$.family') = ?6))
               AND (?7 IS NULL OR (json_valid(payload) AND json_extract(payload, '$.success') = ?7))
               AND (?8 IS NULL OR instr(lower(comm), lower(?8)) > 0
                    OR instr(lower(process_instance_id), lower(?8)) > 0
                    OR instr(lower(payload), lower(?8)) > 0)",
            params![
                filter.session_id,
                filter.pid,
                filter.process_instance_id,
                filter.from_ns,
                filter.to_ns,
                family,
                success,
                filter.search,
            ],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Query events with investigation filters in deterministic chronological order.
    pub fn query_timeline(&self, filter: &TimelineFilter) -> Result<Vec<Event>> {
        let limit = filter
            .limit
            .map(|l| i64::try_from(l).unwrap_or(i64::MAX))
            .unwrap_or(i64::MAX);
        let offset = i64::try_from(filter.offset).unwrap_or(i64::MAX);
        let event_type = filter.event_type.map(|v| v.as_str());
        let mut stmt = self.connection().prepare(
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
               AND (?4 IS NULL OR process_instance_id = ?4)
               AND (?5 IS NULL OR timestamp_ns >= ?5)
               AND (?6 IS NULL OR timestamp_ns <= ?6)
               AND (?7 IS NULL OR instr(lower(comm), lower(?7)) > 0
                    OR instr(lower(process_instance_id), lower(?7)) > 0
                    OR instr(lower(payload), lower(?7)) > 0)
             ORDER BY timestamp_ns ASC, monotonic_ns ASC, id ASC
             LIMIT ?8 OFFSET ?9",
        )?;
        let rows = stmt.query_map(
            params![
                filter.session_id,
                event_type,
                filter.pid,
                filter.process_instance_id,
                filter.from_ns,
                filter.to_ns,
                filter.search,
                limit,
                offset
            ],
            crate::db::row_to_event,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(crate::error::StorageError::from)
    }

    /// Count events matching investigation filters (for pagination/reporting).
    pub fn count_timeline(&self, filter: &TimelineFilter) -> Result<u64> {
        let event_type = filter.event_type.map(|v| v.as_str());
        let count: i64 = self.connection().query_row(
            "SELECT COUNT(*) FROM events
             WHERE session_id = ?1
               AND (?2 IS NULL OR event_type = ?2)
               AND (?3 IS NULL OR pid = ?3)
               AND (?4 IS NULL OR process_instance_id = ?4)
               AND (?5 IS NULL OR timestamp_ns >= ?5)
               AND (?6 IS NULL OR timestamp_ns <= ?6)
               AND (?7 IS NULL OR instr(lower(comm), lower(?7)) > 0
                    OR instr(lower(process_instance_id), lower(?7)) > 0
                    OR instr(lower(payload), lower(?7)) > 0)",
            params![
                filter.session_id,
                event_type,
                filter.pid,
                filter.process_instance_id,
                filter.from_ns,
                filter.to_ns,
                filter.search
            ],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Derive per-process-instance evidence from recorded events only.
    pub fn list_process_instances(&self, session_id: &str) -> Result<Vec<ProcessInstanceEvidence>> {
        self.list_process_instances_bounded(session_id, None)
    }

    /// Derive process instances from at most `max_events` events. Analysis uses
    /// this so its process view cannot silently exceed its event-scan bound.
    pub fn list_process_instances_bounded(
        &self,
        session_id: &str,
        max_events: Option<usize>,
    ) -> Result<Vec<ProcessInstanceEvidence>> {
        let mut by_instance: HashMap<String, ProcessInstanceEvidence> = HashMap::new();
        let mut fork_links: Vec<(String, i32, i32, Option<u64>)> = Vec::new(); // (child_instance, parent_pid, child_pid, child_start_ticks)

        let page_size: usize = 1000;
        let mut seen_events: usize = 0;
        let mut offset: usize = 0;
        loop {
            if max_events.is_some_and(|limit| seen_events >= limit) {
                break;
            }
            let page_limit = max_events
                .map(|limit| page_size.min(limit.saturating_sub(seen_events)))
                .unwrap_or(page_size);
            if page_limit == 0 {
                break;
            }
            let mut filter = TimelineFilter::new(session_id);
            filter.limit = Some(page_limit);
            filter.offset = offset;
            let page = self.query_timeline(&filter)?;
            let n = page.len();
            if n == 0 {
                break;
            }
            for ev in &page {
                let entry = by_instance
                    .entry(ev.process_instance_id.clone())
                    .or_insert_with(|| ProcessInstanceEvidence {
                        process_instance_id: ev.process_instance_id.clone(),
                        pid: ev.pid,
                        comm: ev.comm.clone(),
                        executable: None,
                        command_line: None,
                        first_seen_ns: ev.timestamp_ns,
                        last_seen_ns: ev.timestamp_ns,
                        event_count: 0,
                        exit_observed: false,
                        exit_priority: None,
                        parent_pid: ev.ppid,
                        parent_process_instance_id: None,
                        identity_unresolved: false,
                        ancestry_unresolved: false,
                        notes: Vec::new(),
                    });
                entry.event_count += 1;
                if ev.timestamp_ns < entry.first_seen_ns {
                    entry.first_seen_ns = ev.timestamp_ns;
                }
                if ev.timestamp_ns > entry.last_seen_ns {
                    entry.last_seen_ns = ev.timestamp_ns;
                }
                // Prefer non-empty comm; keep latest seen comm as additional evidence not required.
                if entry.comm.is_empty() {
                    entry.comm = ev.comm.clone();
                }
                match &ev.payload {
                    EventPayload::ProcessExec {
                        filename, process, ..
                    } => {
                        if entry.executable.is_none() && !filename.is_empty() {
                            entry.executable = Some(filename.clone());
                        }
                        if entry.parent_pid.is_none() {
                            entry.parent_pid = process.ppid.or(ev.ppid);
                        }
                    }
                    EventPayload::ProcessFork {
                        parent_pid,
                        child_pid,
                        child_start_time_ticks,
                        ..
                    } => {
                        // Fork event is attributed to child instance in current model.
                        entry.parent_pid = Some(*parent_pid);
                        fork_links.push((
                            ev.process_instance_id.clone(),
                            *parent_pid,
                            *child_pid,
                            *child_start_time_ticks,
                        ));
                        if child_start_time_ticks.is_none() {
                            entry.ancestry_unresolved = true;
                        }
                    }
                    EventPayload::ProcessExit {
                        exit_priority,
                        process,
                    } => {
                        entry.exit_observed = true;
                        entry.exit_priority = Some(*exit_priority);
                        if entry.parent_pid.is_none() {
                            entry.parent_pid = process.ppid.or(ev.ppid);
                        }
                    }
                    _ => {}
                }
                if ev.process_instance_id.contains("unknown-") {
                    entry.identity_unresolved = true;
                }
            }
            seen_events += n;
            offset += n;
            if n < page_limit {
                break;
            }
        }

        // Build pid->instances index by observed pid/start evidence for parent correlation.
        // We can only link parent instance confidently when a unique instance with that pid
        // was observed and identity is unambiguous for the relationship; otherwise unresolved.
        let mut pid_instances: HashMap<i32, Vec<String>> = HashMap::new();
        for inst in by_instance.values() {
            pid_instances
                .entry(inst.pid)
                .or_default()
                .push(inst.process_instance_id.clone());
        }
        // Prefer explicit fork observations. They identify the parent PID and, when
        // available, the child start time, which is stronger evidence than a bare
        // PPID that may have been recycled.
        let mut fork_parent_by_child: HashMap<String, (i32, Option<u64>)> = HashMap::new();
        for (child_instance, parent_pid, _child_pid, child_start_ticks) in fork_links {
            fork_parent_by_child.insert(child_instance, (parent_pid, child_start_ticks));
        }

        // Parent linking: best-effort from recorded evidence only. A candidate
        // parent must have been observed alive when the child first appeared;
        // this prevents a recycled PID's later instance from being selected.
        let ids: Vec<String> = by_instance.keys().cloned().collect();
        for id in ids {
            let fork_parent = fork_parent_by_child.get(&id).map(|(pid, _)| *pid);
            let parent_pid =
                fork_parent.or_else(|| by_instance.get(&id).and_then(|i| i.parent_pid));
            if let Some(ppid) = parent_pid {
                let child_first_seen_ns = by_instance
                    .get(&id)
                    .map(|inst| inst.first_seen_ns)
                    .unwrap_or(i64::MIN);
                let candidates: Vec<String> = pid_instances
                    .get(&ppid)
                    .map(|candidates| {
                        candidates
                            .iter()
                            .filter(|candidate| candidate.as_str() != id.as_str())
                            .filter(|candidate| {
                                by_instance.get(*candidate).is_some_and(|parent| {
                                    parent.first_seen_ns <= child_first_seen_ns
                                        && (!parent.exit_observed
                                            || parent.last_seen_ns >= child_first_seen_ns)
                                })
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                if candidates.len() == 1 {
                    if let Some(inst) = by_instance.get_mut(&id) {
                        inst.parent_process_instance_id = Some(candidates[0].clone());
                    }
                } else if let Some(inst) = by_instance.get_mut(&id) {
                    inst.ancestry_unresolved = true;
                    if candidates.len() > 1 {
                        inst.notes.push(
                            "multiple live process instances share parent pid; parent instance ambiguous"
                                .to_owned(),
                        );
                    } else {
                        inst.notes.push(
                            "no plausible parent instance was observed alive at child creation"
                                .to_owned(),
                        );
                    }
                }
            }
        }

        let mut out: Vec<ProcessInstanceEvidence> = by_instance.into_values().collect();
        // Deterministic ordering: first seen, then pid, then instance id.
        out.sort_by(|a, b| {
            a.first_seen_ns
                .cmp(&b.first_seen_ns)
                .then(a.pid.cmp(&b.pid))
                .then(a.process_instance_id.cmp(&b.process_instance_id))
        });
        // Normalize notes/flags
        for inst in &mut out {
            if inst.parent_pid.is_some() && inst.parent_process_instance_id.is_none() {
                inst.ancestry_unresolved = true;
            }
            if inst.ancestry_unresolved
                && !inst.notes.iter().any(|n| {
                    n.contains("parent") || n.contains("ambiguous") || n.contains("unresolved")
                })
            {
                inst.notes.push(
                    "parent process instance not established from recorded evidence".to_owned(),
                );
            }
            if inst.identity_unresolved {
                inst.notes.push(
                    "process identity is provisional/unresolved in recorded evidence".to_owned(),
                );
            }
            inst.notes.sort();
            inst.notes.dedup();
        }
        Ok(out)
    }

    /// Compute session statistics from persisted evidence.
    pub fn session_stats(&self, session_id: &str) -> Result<Option<SessionStats>> {
        let session = match self.get_session(session_id)? {
            Some(s) => s,
            None => return Ok(None),
        };
        let type_counts = self.event_type_counts(session_id)?;
        let mut events_by_type = BTreeMap::new();
        for (et, c) in type_counts {
            events_by_type.insert(et.as_str().to_owned(), c);
        }
        // Unresolved identity: count distinct process instances with unknown marker in id
        let unresolved_identity_count: i64 = self.connection().query_row(
            "SELECT COUNT(DISTINCT process_instance_id) FROM events
             WHERE session_id = ?1 AND process_instance_id LIKE '%:unknown-%'",
            params![session_id],
            |row| row.get(0),
        )?;
        let duration_ns = session
            .ended_at_ns
            .map(|e| e.saturating_sub(session.started_at_ns));
        let evidence_may_be_incomplete = session.ringbuf_lost_events > 0
            || session.userspace_dropped_events > 0
            || session.dropped_events > 0
            || session.malformed_events > 0
            || session.events_persist_failed > 0
            || session.status == crate::db::SessionStatus::Recovered
            || session.status == crate::db::SessionStatus::Interrupted
            || session.status == crate::db::SessionStatus::Starting
            || session.status == crate::db::SessionStatus::Recording
            || unresolved_identity_count > 0;

        Ok(Some(SessionStats {
            session_id: session.id.clone(),
            status: session.status.as_str().to_owned(),
            started_at_ns: session.started_at_ns,
            ended_at_ns: session.ended_at_ns,
            duration_ns,
            process_count: session.process_count,
            event_count: session.event_count,
            events_persisted: if session.events_persisted > 0 {
                session.events_persisted
            } else {
                session.event_count.max(0) as u64
            },
            events_by_type,
            ringbuf_lost_events: session.ringbuf_lost_events,
            userspace_dropped_events: session.userspace_dropped_events,
            dropped_events_total: session.dropped_events,
            malformed_events: session.malformed_events,
            filtered_events: session.filtered_events,
            events_rejected_scope: session.events_rejected_scope,
            events_rejected_malformed: session.events_rejected_malformed,
            events_persist_failed: session.events_persist_failed,
            events_self_filtered: session.events_self_filtered,
            unresolved_identity_count: unresolved_identity_count.max(0) as u64,
            termination_reason: session.termination_reason.clone(),
            target_exit_code: session.target_exit_code,
            target_exit_signal: session.target_exit_signal,
            evidence_may_be_incomplete,
        }))
    }

    /// Load all events for export in deterministic order using bounded paging.
    pub fn load_all_events_for_export(&self, session_id: &str) -> Result<Vec<Event>> {
        let mut all = Vec::new();
        let page_size: usize = 2000;
        let mut offset: usize = 0;
        loop {
            let mut filter = TimelineFilter::new(session_id);
            filter.limit = Some(page_size);
            filter.offset = offset;
            let page = self.query_timeline(&filter)?;
            let n = page.len();
            if n == 0 {
                break;
            }
            all.extend(page);
            offset += n;
            if n < page_size {
                break;
            }
        }
        Ok(all)
    }
}

#[allow(clippy::type_complexity)]
fn parse_file_payload(
    payload: &str,
) -> Result<(String, bool, bool, i32, u32, i64, bool, Option<i32>)> {
    match serde_json::from_str::<EventPayload>(payload)
        .map_err(|err| StorageError::Data(format!("invalid file-open event payload: {err}")))?
    {
        EventPayload::FileOpen {
            path,
            path_is_absolute,
            path_truncated,
            dirfd,
            flags,
            result,
            success,
            errno,
        } => Ok((
            path,
            path_is_absolute,
            path_truncated,
            dirfd,
            flags,
            result,
            success,
            errno,
        )),
        other => Err(StorageError::Data(format!(
            "file-open event contains non-file payload kind {}",
            other.event_type().as_str()
        ))),
    }
}

#[allow(clippy::type_complexity)]
fn parse_connection_payload(
    payload: &str,
) -> Result<(
    AddressFamily,
    Option<String>,
    Option<u16>,
    String,
    u16,
    i64,
    bool,
    Option<i32>,
    bool,
)> {
    match serde_json::from_str::<EventPayload>(payload).map_err(|err| {
        StorageError::Data(format!("invalid network-connect event payload: {err}"))
    })? {
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
        } => Ok((
            family,
            source_address,
            source_port,
            destination_address,
            destination_port,
            result,
            success,
            errno,
            established,
        )),
        other => Err(StorageError::Data(format!(
            "network-connect event contains non-network payload kind {}",
            other.event_type().as_str()
        ))),
    }
}
