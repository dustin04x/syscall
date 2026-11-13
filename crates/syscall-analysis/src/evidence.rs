//! Bounded, read-only evidence loading and presentation helpers.

use std::collections::HashSet;

use syscall_core::{
    AnalysisProcessRef, Event, EventPayload, EvidenceCompleteness, SessionVerificationReport,
    SupportingEvent,
};
use syscall_storage::{
    ProcessInstanceEvidence, SessionStats, SessionSummary, Storage, TimelineFilter,
};

use crate::{AnalysisConfig, AnalysisError, Result};

const PAGE_SIZE: usize = 1_000;
const MAX_SUPPORTING_EVENTS: usize = 100;

pub(crate) struct Evidence {
    pub session: SessionSummary,
    pub stats: SessionStats,
    pub processes: Vec<ProcessInstanceEvidence>,
    pub events: Vec<Event>,
    pub verification: Option<SessionVerificationReport>,
    pub truncated: bool,
    pub limitations: Vec<String>,
}

impl Evidence {
    pub fn load(storage: &Storage, session_id: &str, config: &AnalysisConfig) -> Result<Self> {
        let session = storage
            .get_session(session_id)?
            .ok_or_else(|| AnalysisError::SessionNotFound(session_id.to_owned()))?;
        let stats = storage
            .session_stats(session_id)?
            .ok_or_else(|| AnalysisError::SessionNotFound(session_id.to_owned()))?;
        let processes =
            storage.list_process_instances_bounded(session_id, Some(config.max_events))?;

        let mut base_filter = TimelineFilter::new(session_id);
        let total = storage.count_timeline(&base_filter)?;
        let mut events = Vec::new();
        let mut offset = 0usize;
        while events.len() < config.max_events {
            let remaining = config.max_events - events.len();
            let mut filter = TimelineFilter::new(session_id);
            filter.limit = Some(remaining.min(PAGE_SIZE));
            filter.offset = offset;
            let page = storage.query_timeline(&filter).map_err(|err| {
                AnalysisError::Evidence(format!(
                    "could not read persisted events at offset {offset}: {err}"
                ))
            })?;
            let n = page.len();
            if n == 0 {
                break;
            }
            events.extend(page);
            offset += n;
            if n < remaining.min(PAGE_SIZE) {
                break;
            }
        }
        let truncated = events.len() < usize::try_from(total).unwrap_or(usize::MAX);
        base_filter.limit = None;

        let (verification, verification_error) = match storage.verify_session(session_id) {
            Ok(report) => (Some(report), None),
            Err(err) => (None, Some(err.to_string())),
        };

        let mut limitations = Vec::new();
        if truncated {
            limitations.push(format!(
                "Event scan stopped at the configured max_events bound ({}); activity after that bound was not analyzed.",
                config.max_events
            ));
        }
        if stats.ringbuf_lost_events > 0 {
            limitations.push(format!(
                "Ring-buffer lost {} event(s); absence of activity is not proof that it did not occur.",
                stats.ringbuf_lost_events
            ));
        }
        if stats.userspace_dropped_events > 0 {
            limitations.push(format!(
                "Userspace dropped {} event(s); negative conclusions are limited.",
                stats.userspace_dropped_events
            ));
        }
        if stats.dropped_events_total > 0 {
            limitations.push(format!(
                "Recorded dropped_events counter is {}.",
                stats.dropped_events_total
            ));
        }
        if stats.malformed_events > 0 {
            limitations.push(format!(
                "{} malformed event(s) were reported by the recorder.",
                stats.malformed_events
            ));
        }
        if stats.events_persist_failed > 0 {
            limitations.push(format!(
                "{} event(s) failed persistence; the database is incomplete.",
                stats.events_persist_failed
            ));
        }
        if stats.unresolved_identity_count > 0 {
            limitations.push(format!(
                "{} process instance(s) have provisional/unresolved identity.",
                stats.unresolved_identity_count
            ));
        }
        let ambiguous_ancestry = processes
            .iter()
            .filter(|process| process.ancestry_unresolved)
            .count();
        if ambiguous_ancestry > 0 {
            limitations.push(format!(
                "{ambiguous_ancestry} process instance(s) have unresolved or ambiguous ancestry; process-tree correlation is limited."
            ));
        }
        if let Some(err) = verification_error {
            limitations.push(format!(
                "Read-only verification could not be completed: {err}. Confidence in cross-event conclusions is reduced."
            ));
        }
        if stats.status != "completed" {
            limitations.push(format!(
                "Session status is {:?}; analysis cannot assume the recording represents a complete target lifetime.",
                stats.status
            ));
        }
        if events.iter().any(|event| event.id.is_none()) {
            limitations.push(
                "Some events had no persisted row id and were not eligible as supporting evidence."
                    .to_owned(),
            );
        }
        let mut seen = HashSet::new();
        limitations.retain(|value| seen.insert(value.clone()));
        limitations.sort();

        Ok(Self {
            session,
            stats,
            processes,
            events,
            verification,
            truncated,
            limitations,
        })
    }

    pub fn complete(&self) -> bool {
        self.completeness().is_complete()
    }

    pub fn completeness(&self) -> EvidenceCompleteness {
        let verification_assessment = self
            .verification
            .as_ref()
            .map(|report| report.assessment.as_str().to_owned());
        let verification_valid = verification_assessment.as_deref() == Some("valid");
        let may_be_incomplete = self.stats.evidence_may_be_incomplete
            || self.truncated
            || !verification_valid
            || self.stats.status != "completed";
        let mut notes = self.limitations.clone();
        if !verification_valid {
            notes.push(
                "Verification is not `valid`; this is an explicit evidence-quality limitation, not a finding of malware."
                    .to_owned(),
            );
        }
        notes.sort();
        notes.dedup();
        EvidenceCompleteness {
            status: if may_be_incomplete {
                "incomplete".to_owned()
            } else {
                "complete".to_owned()
            },
            session_status: self.stats.status.clone(),
            event_count: self.stats.event_count,
            process_count: self.stats.process_count,
            ringbuf_lost_events: self.stats.ringbuf_lost_events,
            userspace_dropped_events: self.stats.userspace_dropped_events,
            malformed_events: self.stats.malformed_events,
            filtered_events: self.stats.filtered_events,
            events_persist_failed: self.stats.events_persist_failed,
            events_self_filtered: self.stats.events_self_filtered,
            unresolved_identity_count: self.stats.unresolved_identity_count,
            verification_assessment,
            may_be_incomplete,
            notes,
        }
    }

    pub fn process(&self, instance_id: &str) -> Option<&ProcessInstanceEvidence> {
        self.processes
            .iter()
            .find(|process| process.process_instance_id == instance_id)
    }

    pub fn process_ref(&self, instance_id: &str) -> Option<AnalysisProcessRef> {
        self.process(instance_id).map(|process| AnalysisProcessRef {
            process_instance_id: process.process_instance_id.clone(),
            pid: process.pid,
            comm: process.comm.clone(),
            executable: process.executable.clone(),
            parent_process_instance_id: process.parent_process_instance_id.clone(),
            exit_observed: process.exit_observed,
        })
    }

    pub fn supporting_event(&self, event: &Event) -> Option<SupportingEvent> {
        Some(SupportingEvent {
            event_id: event.id.filter(|id| *id > 0)?,
            timestamp_ns: event.timestamp_ns,
            monotonic_ns: event.monotonic_ns,
            event_type: event.event_type,
            pid: event.pid,
            process_instance_id: event.process_instance_id.clone(),
            comm: event.comm.clone(),
            summary: event_summary(event),
        })
    }

    pub fn supporting_events(&self, events: &[&Event]) -> Vec<SupportingEvent> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for event in events {
            if out.len() >= MAX_SUPPORTING_EVENTS {
                break;
            }
            if let Some(support) = self.supporting_event(event) {
                if seen.insert(support.event_id) {
                    out.push(support);
                }
            }
        }
        out.sort_by(|a, b| {
            a.timestamp_ns
                .cmp(&b.timestamp_ns)
                .then(a.monotonic_ns.cmp(&b.monotonic_ns))
                .then(a.event_id.cmp(&b.event_id))
        });
        out
    }

    pub fn children_map(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut children: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for process in &self.processes {
            if let Some(parent) = &process.parent_process_instance_id {
                children
                    .entry(parent.clone())
                    .or_default()
                    .push(process.process_instance_id.clone());
            }
        }
        for values in children.values_mut() {
            values.sort();
        }
        children
    }

    pub fn parent_map(&self) -> std::collections::BTreeMap<String, String> {
        self.processes
            .iter()
            .filter_map(|process| {
                process
                    .parent_process_instance_id
                    .as_ref()
                    .map(|parent| (process.process_instance_id.clone(), parent.clone()))
            })
            .collect()
    }
}

pub fn event_summary(event: &Event) -> String {
    match &event.payload {
        EventPayload::ProcessExec { filename, .. } => format!("exec {filename}"),
        EventPayload::ProcessFork {
            parent_pid,
            child_pid,
            child_comm,
            ..
        } => format!("fork parent_pid={parent_pid} child_pid={child_pid} comm={child_comm}"),
        EventPayload::ProcessExit { exit_priority, .. } => {
            format!("exit priority={exit_priority}")
        }
        EventPayload::FileOpen {
            path,
            result,
            success,
            errno,
            path_is_absolute,
            path_truncated,
            ..
        } => format!(
            "open path={path:?} absolute={path_is_absolute} truncated={path_truncated} result={result} success={success} errno={errno:?}"
        ),
        EventPayload::NetworkConnect {
            family,
            destination_address,
            destination_port,
            result,
            success,
            errno,
            ..
        } => format!(
            "connect {family} {destination_address}:{destination_port} result={result} success={success} errno={errno:?}"
        ),
    }
}
