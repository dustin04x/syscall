//! Recording orchestration: load, attach, scope, capture, persist.
//!
//! Privilege model:
//!   1. Load and attach eBPF while running as root/with capabilities.
//!   2. Drop to the invoking user (when started through sudo) so the target
//!      command and the database are owned by that user.
//!   3. Poll the already-mapped ring buffer without further privilege.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::time::{Duration, Instant};

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBuffer, RingBufferBuilder};
use syscall_core::clock;
use syscall_core::ids;
use syscall_core::{
    Event, EventPayload, EventType, ProcessMetadata, RecordingScope, COMM_LEN, SCHEMA_VERSION,
};
use syscall_storage::{
    lock, NewSession, SessionFinish, SessionLock, SessionStatus, Storage, StorageError,
};
use thiserror::Error;

use crate::bpf::SyscallSkelBuilder;
use crate::event_decoder::{self, DecodedEvent, DecodedPayload};
use crate::procfs;
use crate::scope::{Attribution, ScopeTracker};
use crate::{privilege, signal, writer};

const CHANNEL_CAPACITY: usize = 8192;
/// Bound unresolved fork buffering. When full, the oldest entry is emitted as
/// an explicit unresolved fork instead of being dropped silently.
const MAX_BUFFERED_FORKS: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const DRAIN_AFTER_TARGET_EXIT: Duration = Duration::from_millis(750);
const SIGTERM_GRACE: Duration = Duration::from_secs(2);
const DRAIN_AFTER_SIGNAL: Duration = Duration::from_millis(500);

#[derive(Debug, Error)]
pub enum CollectorError {
    #[error("invalid recording request: {0}")]
    InvalidRequest(String),

    #[error("insufficient privileges: {0}")]
    InsufficientPrivilege(String),

    #[error("privilege drop failed: {0}")]
    PrivilegeDrop(String),

    #[error("failed to open BPF skeleton: {0}")]
    Open(String),

    #[error("failed to load BPF programs into the kernel: {0}")]
    Load(String),

    #[error("failed to attach BPF tracepoints: {0}")]
    Attach(String),

    #[error("failed to create ring buffer: {0}")]
    RingBuffer(String),

    #[error("failed to spawn target: {0}")]
    Spawn(String),

    #[error("BPF runtime error: {0}")]
    Bpf(String),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct RecordRequest {
    pub database_path: PathBuf,
    pub command: Vec<OsString>,
    pub scope: RecordingScope,
    pub redact_arguments: bool,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct RejectionBreakdown {
    /// Raw ring-buffer callback deliveries observed by userspace.
    pub ring_samples: u64,
    /// Samples successfully decoded into lifecycle events.
    pub decoded: u64,
    /// Decoded exec events (before attribution).
    pub decoded_exec: u64,
    /// Decoded fork events (before attribution).
    pub decoded_fork: u64,
    /// Decoded exit events (before attribution).
    pub decoded_exit: u64,
    /// Rejected because the event is thread-context (pid!=tgid / thread fork).
    pub thread_context: u64,
    /// Rejected by target-tree attribution (outside scope or unknown lineage).
    pub out_of_scope: u64,
}

#[derive(Debug, Clone)]
pub struct RecordReport {
    pub session_id: String,
    pub status: SessionStatus,
    pub events_persisted: u64,
    /// Total filtered/rejected events (thread context + out of scope).
    pub events_filtered: u64,
    /// Samples discarded because the collector generated them itself.
    pub events_self_filtered: u64,
    pub malformed_events: u64,
    pub ringbuf_lost_events: u64,
    pub userspace_dropped_events: u64,
    pub rejections: RejectionBreakdown,
    pub target: Option<TargetOutcome>,
    pub interrupted: bool,
    /// The signal that interrupted recording (SIGINT/SIGTERM), if any.
    pub interrupt_signal: Option<i32>,
    pub duration_ns: i64,
    pub database_path: PathBuf,
}

/// Load, attach, execute the target, and persist process lifecycle events.
pub fn record(request: RecordRequest) -> Result<RecordReport, CollectorError> {
    validate_request(&request)?;

    let privileges = privilege::inspect();
    if !privileges.can_load_bpf {
        return Err(CollectorError::InsufficientPrivilege(format!(
            "BPF loading requires effective UID 0 or CAP_BPF+CAP_PERFMON (current euid={}, {})",
            privileges.effective_uid, privileges.reason
        )));
    }

    let boot_id = procfs::read_boot_id().unwrap_or_else(|| "unknown-boot".to_owned());
    let kernel_release = procfs::read_kernel_release().unwrap_or_else(|| "unknown".to_owned());
    let session_id = request
        .session_id
        .clone()
        .unwrap_or_else(ids::new_session_id);
    validate_session_id(&session_id)?;
    let clock_offset = clock::wall_offset_ns()?;

    signal::install()?;

    // ----- Phase 1: privileged BPF setup ---------------------------------
    let mut open_object = MaybeUninit::uninit();
    let open_skel = SyscallSkelBuilder::default()
        .open(&mut open_object)
        .map_err(|err| CollectorError::Open(err.to_string()))?;
    // Resolve observer PID namespace metadata for BPF correlation.
    // NOTE: observer_pidns is a normal BPF array map (SEC(".maps")), not mmaped
    // global data. libbpf bpf_map__set_initial_value returns -EINVAL for
    // non-mmaped maps, so we must update element 0 after load() and before
    // attach(). This is the fix for the observed
    // "Invalid argument (os error 22)" during configuration: that error came
    // from userspace map initial-value setup, not from the BPF helper.
    let observer_pidns_meta = match procfs::read_pidns_dev_ino(std::process::id() as i32) {
        Some((dev, ino)) => {
            tracing::debug!(
                phase = "namespace_metadata",
                dev,
                ino,
                "acquired observer PID namespace for BPF correlation"
            );
            Some((dev, ino))
        }
        None => {
            tracing::debug!(
                phase = "namespace_metadata",
                "observer PID namespace not configured (procfs unavailable)"
            );
            None
        }
    };

    let mut skel = open_skel.load().map_err(|err| {
        CollectorError::Load(format!(
            "{err}. On WSL2 verify that the kernel permits BPF loading and run with sudo"
        ))
    })?;
    tracing::debug!(phase = "bpf_load", "BPF skeleton loaded");

    if let Some((dev, ino)) = observer_pidns_meta {
        // struct observer_pidns { __u64 dev; __u64 ino; __u32 configured; __u32 _pad; }
        let mut value = [0u8; 24];
        value[0..8].copy_from_slice(&dev.to_ne_bytes());
        value[8..16].copy_from_slice(&ino.to_ne_bytes());
        value[16..20].copy_from_slice(&1u32.to_ne_bytes());
        let key = 0u32.to_ne_bytes();
        match skel
            .maps
            .observer_pidns
            .update(&key, &value, libbpf_rs::MapFlags::ANY)
        {
            Ok(()) => tracing::debug!(
                phase = "bpf_map_update",
                dev,
                ino,
                "configured observer PID namespace BPF map (pre-attach)"
            ),
            Err(err) => tracing::warn!(
                phase = "bpf_map_update",
                error = %err,
                dev,
                ino,
                "failed to update observer PID namespace BPF map; cross-namespace attribution may be degraded"
            ),
        }
    }

    skel.attach()
        .map_err(|err| CollectorError::Attach(err.to_string()))?;
    tracing::debug!(phase = "bpf_attach", "BPF programs attached");

    // ----- Phase 2: reduce privilege before writing or spawning ----------
    let sudo_user = sudo_user()?;
    if let Some(user) = &sudo_user {
        drop_privileges(user)?;
    }
    // Restrict permissions on the database, WAL sidecars, and any files the
    // target creates through the normal umask.
    // SAFETY: umask has no preconditions.
    unsafe {
        libc::umask(0o077);
    }

    // Hold an exclusive per-session ownership lock for the full recording
    // lifetime so recovery cannot reclaim an active collector. Acquire it
    // after privilege drop so `<db>.locks/` and its file are owned by the
    // invoking user; otherwise the unprivileged writer cannot open them.
    let _session_lock: SessionLock = lock::acquire_exclusive(&request.database_path, &session_id)?;

    // ----- Phase 3: session metadata and writer --------------------------
    let started_at_ns = clock::realtime_now_ns()?;
    let storage = Storage::open(&request.database_path)?;
    let (command, arguments) = session_command(&request);
    storage.create_session(&NewSession {
        id: session_id.clone(),
        schema_version: SCHEMA_VERSION,
        started_at_ns,
        command,
        arguments,
        recording_scope: request.scope,
        boot_id: Some(boot_id.clone()),
        kernel_release: Some(kernel_release),
        collector_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    })?;
    let mut session_guard = SessionGuard::new(&storage, session_id.clone());

    // ----- Phase 4: spawn the target -------------------------------------
    let mut command = Command::new(&request.command[0]);
    command.args(&request.command[1..]).process_group(0);
    let child = command.spawn().map_err(|err| {
        CollectorError::Spawn(format!("failed to execute {:?}: {err}", request.command[0]))
    })?;
    let root_pid = i32::try_from(child.id())
        .map_err(|_| CollectorError::Spawn("child pid does not fit in i32".to_owned()))?;
    let mut target = TargetGuard::new(child, root_pid);

    storage.update_session_status(&session_id, SessionStatus::Recording)?;

    // Read by the userspace/collector-namespace PID (Child::id()) so /proc
    // enrichment works even when BPF observes a different PID namespace.
    let root_proc_pid = root_pid;
    let root_info = procfs::read(root_proc_pid);
    let root_comm = root_info
        .as_ref()
        .map(|info| info.comm.clone())
        .unwrap_or_else(|| command_basename(&request.command[0]));
    let mut root_aliases = root_info
        .as_ref()
        .map(|info| info.id_aliases())
        .unwrap_or_else(|| vec![root_proc_pid]);
    if !root_aliases.contains(&root_proc_pid) {
        root_aliases.push(root_proc_pid);
    }
    // Canonicalize by observer-namespace PID: BPF emits this as hdr.ns_tgid
    // (via bpf_get_ns_current_pid_tgid for the collector PID namespace).
    // BPF hdr.pid/tgid may be in a different namespace (e.g. init/level-0 on
    // global tracepoints); resolve_observed learns those as aliases when
    // ns_tgid matches. NSpid ordering follows proc_pid_status(5): leftmost is
    // the reader/proc-view namespace, rightmost is the innermost namespace;
    // the initial PID namespace ID is not generally discoverable from an inner
    // namespace's /proc view.
    let root_canonical_pid = root_proc_pid;
    let root_innermost_ns_pid = root_info
        .as_ref()
        .map(|info| info.innermost_ns_pid())
        .unwrap_or(root_proc_pid);
    let mut scope = ScopeTracker::new(request.scope, boot_id.clone());
    scope.register_root_with_aliases(
        root_canonical_pid,
        &root_aliases,
        root_info.as_ref().map(|info| info.ppid),
        root_info.as_ref().and_then(|info| info.start_time_ticks),
        &root_comm,
        clock::monotonic_now_ns().unwrap_or(0),
    );

    tracing::info!(
        root_proc_pid,
        root_canonical_pid,
        root_innermost_ns_pid,
        root_nspid = ?root_info.as_ref().map(|i| &i.nspid),
        root_nstgid = ?root_info.as_ref().map(|i| &i.nstgid),
        root_pidns = ?procfs::read_pidns_dev_ino(root_proc_pid),
        collector_pid = std::process::id(),
        collector_nspid = ?procfs::read(std::process::id() as i32).map(|i| i.nspid),
        collector_pidns = ?procfs::read_pidns_dev_ino(std::process::id() as i32),
        ?root_info,
        scope = %request.scope,
        session_id = %session_id,
        "registered target root process (ns_tgid correlation enabled)"
    );

    // ----- Phase 5: ring buffer and callback -----------------------------
    let (event_tx, event_rx) = sync_channel::<Event>(CHANNEL_CAPACITY);
    let collector_pid = std::process::id() as i32;
    let self_samples = AtomicU64::new(0);
    let channel_dropped = AtomicU64::new(0);
    let malformed = AtomicU64::new(0);
    let ring_samples = AtomicU64::new(0);
    let decoded = AtomicU64::new(0);
    let decoded_exec = AtomicU64::new(0);
    let decoded_fork = AtomicU64::new(0);
    let decoded_exit = AtomicU64::new(0);
    let rejected_thread = AtomicU64::new(0);
    let rejected_scope = AtomicU64::new(0);
    let session_id_cb = session_id.clone();
    let boot_id_cb = boot_id.clone();
    let mut fork_buffer: HashMap<i32, BufferedFork> = HashMap::new();

    let mut ring_builder = RingBufferBuilder::new();
    ring_builder
        .add(&skel.maps.events, |data: &[u8]| -> i32 {
            ring_samples.fetch_add(1, Ordering::Relaxed);
            match event_decoder::decode(data) {
                Ok(raw) => {
                    decoded.fetch_add(1, Ordering::Relaxed);
                    // The collector's own /proc enrichment opens files. Those
                    // openat events would themselves trigger more enrichment,
                    // creating an unbounded feedback loop inside ring.poll().
                    // Drop self-originated samples before any build_event call.
                    if is_collector_self(&raw, collector_pid) {
                        self_samples.fetch_add(1, Ordering::Relaxed);
                        return 0;
                    }
                    match raw.event_type {
                        EventType::ProcessExec => {
                            decoded_exec.fetch_add(1, Ordering::Relaxed);
                        }
                        EventType::ProcessFork => {
                            decoded_fork.fetch_add(1, Ordering::Relaxed);
                        }
                        EventType::ProcessExit => {
                            decoded_exit.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    match build_event(
                        &raw,
                        &mut scope,
                        &mut fork_buffer,
                        &session_id_cb,
                        &boot_id_cb,
                        clock_offset,
                    ) {
                        BuildOutcome::Included(events) => {
                            for event in events {
                                tracing::debug!(
                                    event_type = %raw.event_type,
                                    raw_bpf_pid = raw.pid,
                                    raw_bpf_tgid = raw.tgid,
                                    ns_tgid = if raw.ns_tgid > 0 { Some(raw.ns_tgid) } else { None },
                                    canonical_persisted_pid = event.pid,
                                    process_instance_id = %event.process_instance_id,
                                    comm = %event.comm,
                                    "identity chain: raw_bpf -> ns_tgid/canonical -> persisted"
                                );
                                if event_tx.try_send(event).is_err() {
                                    channel_dropped.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        BuildOutcome::Rejected(reason) => {
                            match reason {
                                RejectReason::ThreadContext => {
                                    rejected_thread.fetch_add(1, Ordering::Relaxed);
                                }
                                RejectReason::OutOfScope => {
                                    rejected_scope.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            log_rejection(&raw, reason, scope.root_pid(), scope.tracked_count());
                        }
                    }
                }
                Err(err) => {
                    malformed.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(error = %err, "discarding malformed ring-buffer sample");
                }
            }
            0
        })
        .map_err(|err| CollectorError::RingBuffer(err.to_string()))?;
    let ring = ring_builder
        .build()
        .map_err(|err| CollectorError::RingBuffer(err.to_string()))?;

    let writer_handle = writer::spawn(request.database_path.clone(), session_id.clone(), event_rx);

    // ----- Phase 6: collect until target exit or Ctrl+C ------------------
    let poll_result = poll_target(&ring, &mut target);

    // Stop the callback and close the bounded channel before joining.
    drop(ring);
    // Flush any buffered forks whose canonical identity was never resolved
    // (e.g. child lost to signal before exec/exit correlation). Preserve raw
    // identity explicitly; do not fabricate observer-visible identity.
    for (raw_tgid, buffered) in fork_buffer.drain() {
        if let Some(event) =
            flush_unresolved_fork(buffered, raw_tgid, &boot_id, &session_id, &scope)
        {
            if event_tx.try_send(event).is_err() {
                channel_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let ringbuf_lost = read_ringbuf_lost(&skel);
    drop(event_tx);
    let writer_result = writer_handle.join();
    let ended_at_ns = clock::realtime_now_ns().unwrap_or(started_at_ns);

    let self_samples_count = self_samples.load(Ordering::Relaxed);
    let rejections = RejectionBreakdown {
        ring_samples: ring_samples.load(Ordering::Relaxed),
        decoded: decoded.load(Ordering::Relaxed),
        decoded_exec: decoded_exec.load(Ordering::Relaxed),
        decoded_fork: decoded_fork.load(Ordering::Relaxed),
        decoded_exit: decoded_exit.load(Ordering::Relaxed),
        thread_context: rejected_thread.load(Ordering::Relaxed),
        out_of_scope: rejected_scope.load(Ordering::Relaxed),
    };
    // Best-effort BPF observer namespace helper diagnostics.
    let obs_key = 0u32.to_ne_bytes();
    match skel
        .maps
        .observer_ns_stats
        .lookup(&obs_key, libbpf_rs::MapFlags::ANY)
    {
        Ok(Some(obs_bytes)) if obs_bytes.len() >= 24 => {
            let configured_calls = u64::from_ne_bytes(obs_bytes[0..8].try_into().unwrap_or([0; 8]));
            let ns_tgid_resolved =
                u64::from_ne_bytes(obs_bytes[8..16].try_into().unwrap_or([0; 8]));
            let ns_tgid_helper_error =
                u64::from_ne_bytes(obs_bytes[16..24].try_into().unwrap_or([0; 8]));
            tracing::info!(
                phase = "bpf_helper_stats",
                configured_calls,
                ns_tgid_resolved,
                ns_tgid_helper_error,
                "observer ns_tgid helper stats (helper runs in BPF per exec/exit/fork event when configured; nonzero helper_error means bpf_get_ns_current_pid_tgid returned an error)"
            );
        }
        Ok(_) => tracing::warn!(
            phase = "bpf_helper_stats",
            "observer_ns_stats map lookup returned unexpected value layout"
        ),
        Err(err) => {
            tracing::warn!(phase = "bpf_helper_stats", error = %err, "failed to read observer_ns_stats map")
        }
    }

    tracing::info!(
        ring_samples = rejections.ring_samples,
        decoded = rejections.decoded,
        decoded_exec = rejections.decoded_exec,
        decoded_fork = rejections.decoded_fork,
        decoded_exit = rejections.decoded_exit,
        rejected_thread = rejections.thread_context,
        rejected_out_of_scope = rejections.out_of_scope,
        collector_self_samples = self_samples_count,
        root_canonical_pid = scope.root_pid().unwrap_or(root_proc_pid),
        root_proc_pid,
        "ring-buffer attribution summary"
    );

    let poll_outcome = match poll_result {
        Ok(outcome) => outcome,
        Err(err) => {
            let filtered_events = rejections.thread_context + rejections.out_of_scope;
            let _ = session_guard.finish(SessionFinish {
                ended_at_ns,
                status: SessionStatus::Failed,
                dropped_events: ringbuf_lost + channel_dropped.load(Ordering::Relaxed),
                ringbuf_lost_events: ringbuf_lost,
                userspace_dropped_events: channel_dropped.load(Ordering::Relaxed),
                malformed_events: malformed.load(Ordering::Relaxed),
                filtered_events,
                error: Some(err.to_string()),
                termination_reason: Some("collector_error".to_owned()),
                target_exit_code: None,
                target_exit_signal: None,
                recovered_from_status: None,
                recovered_at_ns: None,
                finalized_at_ns: Some(ended_at_ns),
                events_received: rejections.ring_samples,
                events_decoded: rejections.decoded,
                events_attributed: rejections
                    .decoded
                    .saturating_sub(filtered_events + self_samples_count),
                events_persisted: 0,
                events_rejected_scope: rejections.out_of_scope,
                events_rejected_malformed: malformed.load(Ordering::Relaxed),
                events_persist_failed: 0,
                events_self_filtered: self_samples_count,
            });
            return Err(err);
        }
    };

    let (writer_stats, writer_error) = match writer_result {
        Ok(outcome) => (
            outcome.stats,
            outcome
                .error
                .map(|err| format!("event writer failed: {err}")),
        ),
        Err(_) => (
            writer::WriterStats::default(),
            Some("event writer thread panicked".to_owned()),
        ),
    };

    let userspace_dropped = channel_dropped.load(Ordering::Relaxed);
    let malformed_events = malformed.load(Ordering::Relaxed);
    let filtered_events = rejections.thread_context + rejections.out_of_scope;
    let dropped_events = ringbuf_lost + userspace_dropped;
    let status = if writer_error.is_some() {
        SessionStatus::Failed
    } else if poll_outcome.interrupt_signal.is_some() {
        SessionStatus::Interrupted
    } else {
        SessionStatus::Completed
    };

    let target_outcome = poll_outcome.exit_status.map(|status| TargetOutcome {
        exit_code: status.code(),
        signal: status.signal(),
    });
    let termination_reason = if writer_error.is_some() {
        Some("storage_write_failure".to_owned())
    } else if poll_outcome.interrupt_signal.is_some() {
        Some("interrupted".to_owned())
    } else {
        Some("target_exit".to_owned())
    };

    session_guard.finish(SessionFinish {
        ended_at_ns,
        status,
        dropped_events,
        ringbuf_lost_events: ringbuf_lost,
        userspace_dropped_events: userspace_dropped,
        malformed_events,
        filtered_events,
        error: writer_error.clone(),
        termination_reason,
        target_exit_code: target_outcome.as_ref().and_then(|t| t.exit_code),
        target_exit_signal: target_outcome.as_ref().and_then(|t| t.signal),
        recovered_from_status: None,
        recovered_at_ns: None,
        finalized_at_ns: Some(ended_at_ns),
        events_received: rejections.ring_samples,
        events_decoded: rejections.decoded,
        events_attributed: rejections.decoded.saturating_sub(
            rejections.thread_context + rejections.out_of_scope + self_samples_count,
        ),
        events_persisted: writer_stats.persisted,
        events_rejected_scope: rejections.out_of_scope,
        events_rejected_malformed: malformed_events,
        events_persist_failed: if writer_error.is_some() { 1 } else { 0 },
        events_self_filtered: self_samples_count,
    })?;

    Ok(RecordReport {
        session_id,
        status,
        events_persisted: writer_stats.persisted,
        events_filtered: filtered_events,
        events_self_filtered: self_samples_count,
        malformed_events,
        ringbuf_lost_events: ringbuf_lost,
        userspace_dropped_events: userspace_dropped,
        rejections,
        target: target_outcome,
        interrupted: poll_outcome.interrupt_signal.is_some(),
        interrupt_signal: poll_outcome.interrupt_signal,
        duration_ns: ended_at_ns.saturating_sub(started_at_ns),
        database_path: request.database_path,
    })
}

fn validate_request(request: &RecordRequest) -> Result<(), CollectorError> {
    let Some(program) = request.command.first() else {
        return Err(CollectorError::InvalidRequest(
            "a target command is required after --".to_owned(),
        ));
    };
    let bytes = program.as_bytes();
    if bytes.is_empty() {
        return Err(CollectorError::InvalidRequest(
            "target command path is empty".to_owned(),
        ));
    }
    if bytes.contains(&0) {
        return Err(CollectorError::InvalidRequest(
            "target command contains a NUL byte".to_owned(),
        ));
    }
    if request.database_path.as_os_str().is_empty() {
        return Err(CollectorError::InvalidRequest(
            "database path is empty".to_owned(),
        ));
    }
    Ok(())
}

fn validate_session_id(id: &str) -> Result<(), CollectorError> {
    if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
        return Err(CollectorError::InvalidRequest(
            "session id must be 1..=128 non-control characters".to_owned(),
        ));
    }
    Ok(())
}

fn session_command(request: &RecordRequest) -> (String, Vec<String>) {
    let command = request.command[0].to_string_lossy().into_owned();
    let mut arguments = request.command[1..]
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if request.redact_arguments && !arguments.is_empty() {
        arguments = vec!["<redacted>".to_owned()];
    }
    (command, arguments)
}

fn command_basename(program: &OsString) -> String {
    std::path::Path::new(program)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "target".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// Thread context (exec/exit where pid!=tgid) or thread-creation fork.
    ThreadContext,
    /// Not part of the requested recording scope.
    OutOfScope,
}

#[derive(Debug, Clone)]
pub(crate) enum BuildOutcome {
    Included(Vec<Event>),
    Rejected(RejectReason),
}

#[derive(Debug, Clone)]
struct BufferedFork {
    raw_bpf_parent_tgid: i32,
    timestamp_ns: i64,
    monotonic_ns: u64,
    uid: u32,
    gid: u32,
}

fn log_rejection(raw: &DecodedEvent, reason: RejectReason, root_pid: Option<i32>, tracked: usize) {
    let ns_tgid = if raw.ns_tgid > 0 {
        Some(raw.ns_tgid)
    } else {
        None
    };
    match &raw.payload {
        DecodedPayload::Fork {
            parent_pid,
            child_pid,
            child_comm,
            ..
        } => {
            tracing::debug!(
                event_type = %raw.event_type,
                bpf_pid = raw.pid,
                bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                parent_pid,
                child_pid,
                child_comm = %child_comm,
                ?root_pid,
                tracked,
                ?reason,
                "rejected event"
            );
        }
        DecodedPayload::Exec { filename, .. } => {
            tracing::debug!(
                event_type = %raw.event_type,
                bpf_pid = raw.pid,
                bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                comm = %raw.comm,
                filename = %filename,
                ?root_pid,
                tracked,
                ?reason,
                "rejected event"
            );
        }
        DecodedPayload::Exit { .. } => {
            tracing::debug!(
                event_type = %raw.event_type,
                bpf_pid = raw.pid,
                bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                comm = %raw.comm,
                ?root_pid,
                tracked,
                ?reason,
                "rejected event"
            );
        }
        DecodedPayload::FileOpen { path, result, .. } => {
            tracing::debug!(
                event_type = %raw.event_type,
                bpf_pid = raw.pid,
                bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                comm = %raw.comm,
                path = %path,
                result,
                ?root_pid,
                tracked,
                ?reason,
                "rejected event"
            );
        }
        DecodedPayload::NetworkConnect {
            destination_address,
            destination_port,
            result,
            ..
        } => {
            tracing::debug!(
                event_type = %raw.event_type,
                bpf_pid = raw.pid,
                bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                comm = %raw.comm,
                destination_address = %destination_address,
                destination_port,
                result,
                ?root_pid,
                tracked,
                ?reason,
                "rejected event"
            );
        }
    }
}

/// True when a sample was generated by the collector process itself.
///
/// `ns_tgid` is the observer-namespace TGID and is the most reliable match;
/// the raw PID/TGID checks cover configurations where the namespace helper is
/// unavailable. Filtering here, before procfs enrichment, is what prevents the
/// collector's own `/proc` reads from recursively generating file-open events.
fn is_collector_self(raw: &DecodedEvent, collector_pid: i32) -> bool {
    raw.pid == collector_pid || raw.tgid == collector_pid || raw.ns_tgid == collector_pid
}

fn source_tracepoint(event_type: EventType) -> &'static str {
    match event_type {
        EventType::ProcessExec => "sched/sched_process_exec",
        EventType::ProcessFork => "sched/sched_process_fork",
        EventType::ProcessExit => "sched/sched_process_exit",
        EventType::FileOpen => "syscalls/sys_exit_openat",
        EventType::NetworkConnect => "syscalls/sys_exit_connect",
    }
}

fn event_provenance(
    raw: &DecodedEvent,
    attribution_method: &'static str,
) -> syscall_core::EventProvenance {
    let ns_tgid = if raw.ns_tgid > 0 {
        Some(raw.ns_tgid)
    } else {
        None
    };
    syscall_core::EventProvenance {
        raw_bpf_pid: Some(raw.pid),
        raw_bpf_tgid: Some(raw.tgid),
        observer_pid: ns_tgid,
        observer_tgid: ns_tgid,
        source_tracepoint: Some(source_tracepoint(raw.event_type).to_owned()),
        wire_schema_version: Some(raw.wire_schema_version),
        attribution_method: Some(attribution_method.to_owned()),
        timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
        monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
    }
}

fn build_event(
    raw: &DecodedEvent,
    scope: &mut ScopeTracker,
    fork_buffer: &mut HashMap<i32, BufferedFork>,
    session_id: &str,
    boot_id: &str,
    clock_offset: i64,
) -> BuildOutcome {
    let timestamp_ns = clock::wall_from_monotonic(clock_offset, raw.monotonic_ns);
    let ns_tgid = if raw.ns_tgid > 0 {
        Some(raw.ns_tgid)
    } else {
        None
    };

    match &raw.payload {
        DecodedPayload::Exec { old_pid, filename } => {
            if raw.pid != raw.tgid {
                return BuildOutcome::Rejected(RejectReason::ThreadContext);
            }
            // /proc enrichment uses BPF PID (may be unavailable across namespaces);
            // attribution uses resolve_observed which correlates via ns_tgid.
            let info = procfs::read(raw.pid).or_else(|| ns_tgid.and_then(procfs::read));
            let cached = scope
                .get(raw.pid)
                .or_else(|| ns_tgid.and_then(|id| scope.get(id)));
            let ppid = info
                .as_ref()
                .map(|value| value.ppid)
                .or_else(|| cached.and_then(|value| value.ppid));
            let start_time_ticks = info
                .as_ref()
                .and_then(|value| value.start_time_ticks)
                .or_else(|| cached.and_then(|value| value.start_time_ticks));
            let comm = normalize_comm(&raw.comm, info.as_ref().map(|value| value.comm.as_str()));
            let root_before = scope.root_pid();
            let attribution = scope.resolve_observed(
                raw.pid,
                ns_tgid,
                ppid,
                None,
                start_time_ticks,
                &comm,
                raw.monotonic_ns,
            );
            let Attribution::Included(tracked) = attribution else {
                tracing::debug!(
                    phase = "scope",
                    event_type = %raw.event_type,
                    bpf_tgid = raw.tgid,
                    ns_tgid = ?ns_tgid,
                    canonical_tgid = ns_tgid.unwrap_or(raw.tgid),
                    ?ppid,
                    ?root_before,
                    tracked = scope.tracked_count(),
                    "scope rejected exec"
                );
                return BuildOutcome::Rejected(RejectReason::OutOfScope);
            };
            tracing::debug!(
                phase = "scope",
                event_type = %raw.event_type,
                raw_bpf_pid = raw.pid,
                raw_bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                canonical_pid = tracked.tgid,
                canonical_ppid = ?tracked.ppid,
                process_instance_id = %tracked.process_instance_id,
                root_pid = ?scope.root_pid(),
                "identity chain: raw_bpf -> ns_tgid -> canonical (scope attributed exec)"
            );
            let mut events = Vec::new();
            if let Some(buffered) = fork_buffer
                .remove(&raw.tgid)
                .or_else(|| fork_buffer.remove(&tracked.raw_tgid.unwrap_or(raw.tgid)))
            {
                events.push(flush_buffered_fork(buffered, &tracked, session_id));
            }
            let uid = info.as_ref().map(|value| value.uid).unwrap_or(raw.uid);
            let gid = info.as_ref().map(|value| value.gid).unwrap_or(raw.gid);
            let attr_method = if ns_tgid.is_some() {
                "ns_tgid_correlated"
            } else {
                "raw_bpf_or_procfs"
            };
            events.push(Event {
                id: None,
                session_id: session_id.to_owned(),
                schema_version: SCHEMA_VERSION,
                event_type: EventType::ProcessExec,
                timestamp_ns,
                monotonic_ns: raw.monotonic_ns,
                pid: tracked.tgid,
                tid: tracked.tgid,
                uid,
                gid,
                ppid: tracked.ppid.or(ppid),
                comm: tracked.comm.clone(),
                process_instance_id: tracked.process_instance_id.clone(),
                payload: EventPayload::ProcessExec {
                    filename: filename.clone(),
                    process: ProcessMetadata {
                        ppid: tracked.ppid.or(ppid),
                        start_time_ticks: tracked.start_time_ticks,
                    },
                    old_pid: (*old_pid > 0).then_some(*old_pid),
                },
                provenance: Some(event_provenance(raw, attr_method)),
            });
            BuildOutcome::Included(events)
        }

        DecodedPayload::Fork {
            parent_pid,
            child_pid,
            child_comm,
            ..
        } => {
            let child_tgid = *child_pid;
            let child_info = procfs::read(child_tgid).or_else(|| ns_tgid.and_then(procfs::read));
            let is_thread = child_info
                .as_ref()
                .map(|value| value.tgid != value.pid)
                .unwrap_or(false);
            if is_thread {
                return BuildOutcome::Rejected(RejectReason::ThreadContext);
            }
            let start_time_ticks = child_info.as_ref().and_then(|value| value.start_time_ticks);
            let comm = normalize_comm(
                child_comm,
                child_info.as_ref().map(|value| value.comm.as_str()),
            );
            let uid = child_info.as_ref().map(|v| v.uid).unwrap_or(raw.uid);
            let gid = child_info.as_ref().map(|v| v.gid).unwrap_or(raw.gid);

            // BPF fork emits ns_tgid=0 (child context unavailable). Resolve
            // observer-visible identity safely when possible; otherwise track
            // provisionally and buffer the fork. Exec/exit in child context
            // provide ns_tgid, allowing a stable process_instance_id across
            // fork/exec/exit without fabricating identity.
            let parent_canonical = scope.canonical_pid(*parent_pid);
            let resolved_observer_tgid = if let Some(ns) = ns_tgid.filter(|v| *v > 0) {
                Some(ns)
            } else {
                child_info.as_ref().and_then(|info| {
                    let info_ppid_canonical = scope.canonical_pid(info.ppid);
                    if info.is_process_leader()
                        && (info_ppid_canonical == parent_canonical
                            || scope.get(info.ppid).is_some()
                            || scope.get(info_ppid_canonical).is_some())
                    {
                        Some(info.pid)
                    } else {
                        None
                    }
                })
            };

            if let Some(observer_tgid) = resolved_observer_tgid {
                let parent_for_resolve = scope.canonical_pid(*parent_pid);
                let tracked = if let Attribution::Included(t) = scope.resolve_observed(
                    observer_tgid,
                    Some(observer_tgid),
                    Some(parent_for_resolve),
                    None,
                    start_time_ticks
                        .or_else(|| child_info.as_ref().and_then(|v| v.start_time_ticks)),
                    &comm,
                    raw.monotonic_ns,
                ) {
                    t
                } else if let Attribution::Included(t) = scope.resolve_observed(
                    child_tgid,
                    Some(observer_tgid),
                    Some(*parent_pid),
                    None,
                    start_time_ticks,
                    &comm,
                    raw.monotonic_ns,
                ) {
                    t
                } else {
                    tracing::debug!(
                        phase = "scope",
                        event_type = %raw.event_type,
                        bpf_child_tgid = child_tgid,
                        observer_tgid,
                        bpf_parent = *parent_pid,
                        root_pid = ?scope.root_pid(),
                        "scope rejected fork (resolved identity not attributable)"
                    );
                    return BuildOutcome::Rejected(RejectReason::OutOfScope);
                };
                scope.register_aliases(tracked.tgid, &[child_tgid, observer_tgid]);
                tracing::debug!(
                    phase = "scope",
                    event_type = %raw.event_type,
                    raw_bpf_tgid = child_tgid,
                    observer_tgid,
                    canonical_pid = tracked.tgid,
                    canonical_ppid = ?tracked.ppid,
                    process_instance_id = %tracked.process_instance_id,
                    "identity chain: raw_bpf -> verified/canonical (scope attributed fork)"
                );
                let attr_method = if ns_tgid.is_some() {
                    "ns_tgid_correlated"
                } else {
                    "observer_pid_verified"
                };
                return BuildOutcome::Included(vec![Event {
                    id: None,
                    session_id: session_id.to_owned(),
                    schema_version: SCHEMA_VERSION,
                    event_type: EventType::ProcessFork,
                    timestamp_ns,
                    monotonic_ns: raw.monotonic_ns,
                    pid: tracked.tgid,
                    tid: tracked.tgid,
                    uid,
                    gid,
                    ppid: tracked.ppid,
                    comm: tracked.comm.clone(),
                    process_instance_id: tracked.process_instance_id.clone(),
                    payload: EventPayload::ProcessFork {
                        parent_pid: tracked.ppid.unwrap_or(parent_canonical),
                        parent_tgid: tracked.ppid,
                        child_pid: tracked.tgid,
                        child_comm: tracked.comm.clone(),
                        child_start_time_ticks: tracked.start_time_ticks,
                    },
                    provenance: Some(event_provenance(raw, attr_method)),
                }]);
            }

            let attribution = scope.register_provisional(
                child_tgid,
                Some(*parent_pid),
                start_time_ticks,
                &comm,
                raw.monotonic_ns,
            );
            let Attribution::Included(provisional) = attribution else {
                tracing::debug!(
                    phase = "scope",
                    event_type = %raw.event_type,
                    bpf_child_tgid = child_tgid,
                    bpf_parent = *parent_pid,
                    root_pid = ?scope.root_pid(),
                    tracked = scope.tracked_count(),
                    "scope rejected fork (provisional)"
                );
                return BuildOutcome::Rejected(RejectReason::OutOfScope);
            };
            tracing::debug!(
                phase = "scope",
                event_type = %raw.event_type,
                raw_bpf_tgid = child_tgid,
                bpf_parent = *parent_pid,
                provisional_canonical = provisional.tgid,
                process_instance_id = %provisional.process_instance_id,
                "fork buffered: child observer identity unknown; awaiting ns_tgid on exec/exit"
            );
            let mut flushed = Vec::new();
            while fork_buffer.len() >= MAX_BUFFERED_FORKS {
                let Some(oldest_tgid) = fork_buffer
                    .iter()
                    .min_by_key(|(_, buffered)| (buffered.timestamp_ns, buffered.monotonic_ns))
                    .map(|(pid, _)| *pid)
                else {
                    break;
                };
                let Some(oldest) = fork_buffer.remove(&oldest_tgid) else {
                    break;
                };
                if let Some(event) =
                    flush_unresolved_fork(oldest, oldest_tgid, boot_id, session_id, scope)
                {
                    flushed.push(event);
                }
            }
            fork_buffer.insert(
                child_tgid,
                BufferedFork {
                    raw_bpf_parent_tgid: *parent_pid,
                    timestamp_ns,
                    monotonic_ns: raw.monotonic_ns,
                    uid,
                    gid,
                },
            );
            BuildOutcome::Included(flushed)
        }

        DecodedPayload::Exit { exit_priority } => {
            if raw.pid != raw.tgid {
                return BuildOutcome::Rejected(RejectReason::ThreadContext);
            }
            let info = procfs::read(raw.pid).or_else(|| ns_tgid.and_then(procfs::read));
            let cached = scope
                .get(raw.pid)
                .or_else(|| ns_tgid.and_then(|id| scope.get(id)));
            let ppid = info
                .as_ref()
                .map(|value| value.ppid)
                .or_else(|| cached.and_then(|value| value.ppid));
            let start_time_ticks = info
                .as_ref()
                .and_then(|value| value.start_time_ticks)
                .or_else(|| cached.and_then(|value| value.start_time_ticks));
            let comm = normalize_comm(&raw.comm, info.as_ref().map(|value| value.comm.as_str()));
            let Attribution::Included(tracked) = scope.resolve_observed(
                raw.pid,
                ns_tgid,
                ppid,
                None,
                start_time_ticks,
                &comm,
                raw.monotonic_ns,
            ) else {
                tracing::debug!(
                    phase = "scope",
                    event_type = %raw.event_type,
                    bpf_tgid = raw.tgid,
                    ns_tgid = ?ns_tgid,
                    ?ppid,
                    root_pid = ?scope.root_pid(),
                    tracked = scope.tracked_count(),
                    "scope rejected exit"
                );
                return BuildOutcome::Rejected(RejectReason::OutOfScope);
            };
            tracing::debug!(
                phase = "scope",
                event_type = %raw.event_type,
                raw_bpf_pid = raw.pid,
                raw_bpf_tgid = raw.tgid,
                ns_tgid = ?ns_tgid,
                canonical_pid = tracked.tgid,
                canonical_ppid = ?tracked.ppid,
                process_instance_id = %tracked.process_instance_id,
                root_pid = ?scope.root_pid(),
                "identity chain: raw_bpf -> ns_tgid -> canonical (scope attributed exit)"
            );
            let mut events = Vec::new();
            if let Some(buffered) = fork_buffer
                .remove(&raw.tgid)
                .or_else(|| fork_buffer.remove(&tracked.raw_tgid.unwrap_or(raw.tgid)))
            {
                events.push(flush_buffered_fork(buffered, &tracked, session_id));
            }
            let uid = info.as_ref().map(|value| value.uid).unwrap_or(raw.uid);
            let gid = info.as_ref().map(|value| value.gid).unwrap_or(raw.gid);
            let attr_method = if ns_tgid.is_some() {
                "ns_tgid_correlated"
            } else {
                "raw_bpf_or_procfs"
            };
            let event = Event {
                id: None,
                session_id: session_id.to_owned(),
                schema_version: SCHEMA_VERSION,
                event_type: EventType::ProcessExit,
                timestamp_ns,
                monotonic_ns: raw.monotonic_ns,
                pid: tracked.tgid,
                tid: tracked.tgid,
                uid,
                gid,
                ppid: tracked.ppid.or(ppid),
                comm: tracked.comm.clone(),
                process_instance_id: tracked.process_instance_id.clone(),
                payload: EventPayload::ProcessExit {
                    process: ProcessMetadata {
                        ppid: tracked.ppid.or(ppid),
                        start_time_ticks: tracked.start_time_ticks,
                    },
                    exit_priority: *exit_priority,
                },
                provenance: Some(event_provenance(raw, attr_method)),
            };
            scope.mark_exited(tracked.tgid);
            events.push(event);
            BuildOutcome::Included(events)
        }

        DecodedPayload::FileOpen {
            path,
            path_is_absolute,
            path_truncated,
            dirfd,
            flags,
            result,
        } => {
            let info = procfs::read(raw.tgid).or_else(|| ns_tgid.and_then(procfs::read));
            let cached = scope
                .get(raw.tgid)
                .or_else(|| ns_tgid.and_then(|id| scope.get(id)));
            let ppid = info
                .as_ref()
                .map(|value| value.ppid)
                .or_else(|| cached.and_then(|value| value.ppid));
            let start_time_ticks = info
                .as_ref()
                .and_then(|value| value.start_time_ticks)
                .or_else(|| cached.and_then(|value| value.start_time_ticks));
            let comm = normalize_comm(&raw.comm, info.as_ref().map(|value| value.comm.as_str()));
            let Attribution::Included(tracked) = scope.resolve_observed(
                raw.tgid,
                ns_tgid,
                ppid,
                None,
                start_time_ticks,
                &comm,
                raw.monotonic_ns,
            ) else {
                return BuildOutcome::Rejected(RejectReason::OutOfScope);
            };
            let success = *result >= 0;
            let errno = if success {
                None
            } else {
                result
                    .checked_neg()
                    .and_then(|value| i32::try_from(value).ok())
            };
            BuildOutcome::Included(vec![Event {
                id: None,
                session_id: session_id.to_owned(),
                schema_version: SCHEMA_VERSION,
                event_type: EventType::FileOpen,
                timestamp_ns,
                monotonic_ns: raw.monotonic_ns,
                pid: tracked.tgid,
                tid: raw.pid,
                uid: info.as_ref().map(|value| value.uid).unwrap_or(raw.uid),
                gid: info.as_ref().map(|value| value.gid).unwrap_or(raw.gid),
                ppid: tracked.ppid.or(ppid),
                comm: tracked.comm.clone(),
                process_instance_id: tracked.process_instance_id.clone(),
                payload: EventPayload::FileOpen {
                    path: path.clone(),
                    path_is_absolute: *path_is_absolute,
                    path_truncated: *path_truncated,
                    dirfd: *dirfd,
                    flags: *flags,
                    result: *result,
                    success,
                    errno,
                },
                provenance: Some(event_provenance(raw, "syscall_pair_attributed")),
            }])
        }

        DecodedPayload::NetworkConnect {
            family,
            source_address,
            source_port,
            destination_address,
            destination_port,
            result,
        } => {
            let info = procfs::read(raw.tgid).or_else(|| ns_tgid.and_then(procfs::read));
            let cached = scope
                .get(raw.tgid)
                .or_else(|| ns_tgid.and_then(|id| scope.get(id)));
            let ppid = info
                .as_ref()
                .map(|value| value.ppid)
                .or_else(|| cached.and_then(|value| value.ppid));
            let start_time_ticks = info
                .as_ref()
                .and_then(|value| value.start_time_ticks)
                .or_else(|| cached.and_then(|value| value.start_time_ticks));
            let comm = normalize_comm(&raw.comm, info.as_ref().map(|value| value.comm.as_str()));
            let Attribution::Included(tracked) = scope.resolve_observed(
                raw.tgid,
                ns_tgid,
                ppid,
                None,
                start_time_ticks,
                &comm,
                raw.monotonic_ns,
            ) else {
                return BuildOutcome::Rejected(RejectReason::OutOfScope);
            };
            let success = *result == 0;
            let errno = if success {
                None
            } else {
                result
                    .checked_neg()
                    .and_then(|value| i32::try_from(value).ok())
            };
            BuildOutcome::Included(vec![Event {
                id: None,
                session_id: session_id.to_owned(),
                schema_version: SCHEMA_VERSION,
                event_type: EventType::NetworkConnect,
                timestamp_ns,
                monotonic_ns: raw.monotonic_ns,
                pid: tracked.tgid,
                tid: raw.pid,
                uid: info.as_ref().map(|value| value.uid).unwrap_or(raw.uid),
                gid: info.as_ref().map(|value| value.gid).unwrap_or(raw.gid),
                ppid: tracked.ppid.or(ppid),
                comm: tracked.comm.clone(),
                process_instance_id: tracked.process_instance_id.clone(),
                payload: EventPayload::NetworkConnect {
                    family: *family,
                    source_address: source_address.clone(),
                    source_port: *source_port,
                    destination_address: destination_address.clone(),
                    destination_port: *destination_port,
                    result: *result,
                    success,
                    errno,
                    established: false,
                },
                provenance: Some(event_provenance(raw, "syscall_pair_attributed")),
            }])
        }
    }
}

fn flush_buffered_fork(
    buffered: BufferedFork,
    tracked: &crate::scope::TrackedProcess,
    session_id: &str,
) -> Event {
    Event {
        id: None,
        session_id: session_id.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: EventType::ProcessFork,
        timestamp_ns: buffered.timestamp_ns,
        monotonic_ns: buffered.monotonic_ns,
        pid: tracked.tgid,
        tid: tracked.tgid,
        uid: buffered.uid,
        gid: buffered.gid,
        ppid: tracked.ppid,
        comm: tracked.comm.clone(),
        process_instance_id: tracked.process_instance_id.clone(),
        payload: EventPayload::ProcessFork {
            parent_pid: tracked.ppid.unwrap_or(buffered.raw_bpf_parent_tgid),
            parent_tgid: tracked.ppid,
            child_pid: tracked.tgid,
            child_comm: tracked.comm.clone(),
            child_start_time_ticks: tracked.start_time_ticks,
        },
        provenance: Some(syscall_core::EventProvenance {
            raw_bpf_pid: tracked.raw_tgid.or(Some(tracked.tgid)),
            raw_bpf_tgid: tracked.raw_tgid.or(Some(tracked.tgid)),
            observer_pid: if tracked.provisional {
                None
            } else {
                Some(tracked.tgid)
            },
            observer_tgid: if tracked.provisional {
                None
            } else {
                Some(tracked.tgid)
            },
            source_tracepoint: Some("sched/sched_process_fork".to_owned()),
            wire_schema_version: Some(2),
            attribution_method: Some("fork_buffered_then_correlated".to_owned()),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
        }),
    }
}

fn flush_unresolved_fork(
    buffered: BufferedFork,
    raw_tgid: i32,
    boot_id: &str,
    session_id: &str,
    scope: &ScopeTracker,
) -> Option<Event> {
    let tracked = scope.get(raw_tgid)?;
    let parent_canonical = tracked.ppid;
    let instance_id = syscall_core::ids::process_instance_id(
        boot_id,
        raw_tgid,
        tracked.start_time_ticks,
        buffered.monotonic_ns,
    );
    tracing::debug!(
        phase = "scope",
        raw_bpf_tgid = raw_tgid,
        canonical_pid = tracked.tgid,
        provisional = tracked.provisional,
        "flushing buffered fork with unresolved/raw identity (no ns_tgid correlation observed)"
    );
    Some(Event {
        id: None,
        session_id: session_id.to_owned(),
        schema_version: SCHEMA_VERSION,
        event_type: EventType::ProcessFork,
        timestamp_ns: buffered.timestamp_ns,
        monotonic_ns: buffered.monotonic_ns,
        pid: tracked.tgid,
        tid: tracked.tgid,
        uid: buffered.uid,
        gid: buffered.gid,
        ppid: parent_canonical,
        comm: tracked.comm.clone(),
        process_instance_id: instance_id,
        payload: EventPayload::ProcessFork {
            parent_pid: parent_canonical.unwrap_or(buffered.raw_bpf_parent_tgid),
            parent_tgid: parent_canonical,
            child_pid: tracked.tgid,
            child_comm: tracked.comm.clone(),
            child_start_time_ticks: tracked.start_time_ticks,
        },
        provenance: Some(syscall_core::EventProvenance {
            raw_bpf_pid: Some(raw_tgid),
            raw_bpf_tgid: Some(raw_tgid),
            observer_pid: None,
            observer_tgid: None,
            source_tracepoint: Some("sched/sched_process_fork".to_owned()),
            wire_schema_version: Some(2),
            attribution_method: Some(
                if tracked.provisional {
                    "fork_unresolved_provisional"
                } else {
                    "fork_unresolved_raw"
                }
                .to_owned(),
            ),
            timestamp_clock_domain: Some("wall_realtime_derived".to_owned()),
            monotonic_clock_domain: Some("monotonic_boot_raw".to_owned()),
        }),
    })
}

fn normalize_comm(primary: &str, fallback: Option<&str>) -> String {
    let value = if !primary.is_empty() {
        primary
    } else {
        fallback
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown")
    };
    let mut result = String::new();
    for character in value.chars() {
        if result.len() + character.len_utf8() >= COMM_LEN {
            break;
        }
        result.push(character);
    }
    if result.is_empty() {
        "unknown".to_owned()
    } else {
        result
    }
}

struct PollOutcome {
    interrupt_signal: Option<i32>,
    exit_status: Option<ExitStatus>,
}

fn is_eintr_bpf(err: &libbpf_rs::Error) -> bool {
    let msg = err.to_string();
    msg.contains("Interrupted system call") || msg.contains("os error 4")
}

fn poll_ring_best_effort(ring: &RingBuffer<'_>, timeout: Duration) {
    match ring.poll(timeout) {
        Ok(_) => {}
        Err(err) if is_eintr_bpf(&err) && signal::requested() => {}
        Err(err) if is_eintr_bpf(&err) => {
            // Unexpected EINTR without shutdown request: retry once via loop caller.
            tracing::debug!(error = %err, "ring buffer poll interrupted (no shutdown request)");
        }
        Err(err) => {
            tracing::debug!(error = %err, "ring buffer poll error during drain (ignored)");
        }
    }
}

fn poll_target(
    ring: &RingBuffer<'_>,
    target: &mut TargetGuard,
) -> Result<PollOutcome, CollectorError> {
    let mut exit_status = None;
    let mut interrupted = false;
    let mut drain_deadline = None;

    loop {
        match ring.poll(POLL_INTERVAL) {
            Ok(_) => {}
            Err(err) if is_eintr_bpf(&err) => {
                if signal::requested() {
                    interrupted = true;
                    break;
                }
                // EINTR without an active shutdown request: not successful
                // completion; just retry and recheck state.
                continue;
            }
            Err(err) => return Err(CollectorError::Bpf(err.to_string())),
        }

        if signal::requested() {
            interrupted = true;
            break;
        }

        if exit_status.is_none() {
            if let Some(status) = target.try_wait()? {
                exit_status = Some(status);
                drain_deadline = Some(Instant::now() + DRAIN_AFTER_TARGET_EXIT);
            }
        }

        if let Some(deadline) = drain_deadline {
            if Instant::now() >= deadline {
                break;
            }
        }
    }

    if interrupted {
        target.signal_group(libc::SIGTERM);
        let deadline = Instant::now() + SIGTERM_GRACE;
        while Instant::now() < deadline {
            poll_ring_best_effort(ring, Duration::from_millis(50));
            if let Some(status) = target.try_wait()? {
                exit_status = Some(status);
                break;
            }
        }
        if exit_status.is_none() {
            exit_status = Some(target.terminate()?);
        }

        let deadline = Instant::now() + DRAIN_AFTER_SIGNAL;
        while Instant::now() < deadline {
            poll_ring_best_effort(ring, Duration::from_millis(50));
        }
    }

    let interrupt_signal = if interrupted {
        signal::requested_signal().or(Some(libc::SIGINT))
    } else {
        None
    };
    Ok(PollOutcome {
        interrupt_signal,
        exit_status,
    })
}

fn read_ringbuf_lost(skel: &crate::bpf::SyscallSkel<'_>) -> u64 {
    let key = 0u32.to_ne_bytes();
    match skel.maps.ringbuf_lost_events.lookup(&key, MapFlags::ANY) {
        Ok(Some(bytes)) if bytes.len() >= 8 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&bytes[..8]);
            u64::from_ne_bytes(raw)
        }
        Ok(_) => 0,
        Err(err) => {
            tracing::warn!(error = %err, "could not read ring-buffer loss counter");
            0
        }
    }
}

struct SessionGuard<'a> {
    storage: &'a Storage,
    session_id: String,
    finalized: bool,
}

impl<'a> SessionGuard<'a> {
    fn new(storage: &'a Storage, session_id: String) -> Self {
        Self {
            storage,
            session_id,
            finalized: false,
        }
    }

    fn finish(&mut self, finish: SessionFinish) -> Result<(), StorageError> {
        self.storage.finish_session(&self.session_id, &finish)?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }
        let now = clock::realtime_now_ns().unwrap_or(0);
        let finish = SessionFinish {
            ended_at_ns: now,
            status: SessionStatus::Failed,
            dropped_events: 0,
            ringbuf_lost_events: 0,
            userspace_dropped_events: 0,
            malformed_events: 0,
            filtered_events: 0,
            error: Some("recording aborted before finalization".to_owned()),
            termination_reason: Some("collector_abort".to_owned()),
            target_exit_code: None,
            target_exit_signal: None,
            recovered_from_status: None,
            recovered_at_ns: None,
            finalized_at_ns: Some(now),
            events_received: 0,
            events_decoded: 0,
            events_attributed: 0,
            events_persisted: 0,
            events_rejected_scope: 0,
            events_rejected_malformed: 0,
            events_persist_failed: 0,
            events_self_filtered: 0,
        };
        if let Err(err) = self.storage.finish_session(&self.session_id, &finish) {
            tracing::error!(error = %err, "failed to finalize aborted session");
        }
    }
}

struct TargetGuard {
    child: Child,
    pgid: i32,
    reaped: bool,
}

impl TargetGuard {
    fn new(child: Child, pgid: i32) -> Self {
        Self {
            child,
            pgid,
            reaped: false,
        }
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn signal_group(&self, signal: libc::c_int) {
        if self.pgid > 0 {
            // SAFETY: kill with a negative pid targets the process group. A
            // vanished group is reported as ESRCH and can be ignored.
            unsafe {
                libc::kill(-self.pgid, signal);
            }
        }
    }

    fn terminate(&mut self) -> io::Result<ExitStatus> {
        self.signal_group(libc::SIGKILL);
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for TargetGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        self.signal_group(libc::SIGKILL);
        // Kill the direct child as a fallback if it changed its process group.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug, Clone, Copy)]
struct SudoUser {
    uid: u32,
    gid: u32,
}

fn sudo_user() -> Result<Option<SudoUser>, CollectorError> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let uid = std::env::var("SUDO_UID").ok();
    let gid = std::env::var("SUDO_GID").ok();
    match (uid, gid) {
        (None, None) => Ok(None),
        (Some(uid), Some(gid)) => {
            let uid = uid.parse::<u32>().map_err(|_| {
                CollectorError::PrivilegeDrop("SUDO_UID is not a valid uid".to_owned())
            })?;
            let gid = gid.parse::<u32>().map_err(|_| {
                CollectorError::PrivilegeDrop("SUDO_GID is not a valid gid".to_owned())
            })?;
            if uid == 0 {
                Ok(None)
            } else {
                Ok(Some(SudoUser { uid, gid }))
            }
        }
        _ => Err(CollectorError::PrivilegeDrop(
            "SUDO_UID and SUDO_GID must both be set or both unset".to_owned(),
        )),
    }
}

fn drop_privileges(user: &SudoUser) -> Result<(), CollectorError> {
    // SAFETY: these calls are the standard irrevocable privilege drop order.
    // All errors are checked before continuing.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(CollectorError::PrivilegeDrop(format!(
                "setgroups failed: {}",
                io::Error::last_os_error()
            )));
        }
        if libc::setgid(user.gid) != 0 {
            return Err(CollectorError::PrivilegeDrop(format!(
                "setgid({}) failed: {}",
                user.gid,
                io::Error::last_os_error()
            )));
        }
        if libc::setuid(user.uid) != 0 {
            return Err(CollectorError::PrivilegeDrop(format!(
                "setuid({}) failed: {}",
                user.uid,
                io::Error::last_os_error()
            )));
        }
    }
    // SAFETY: geteuid/getegid have no preconditions.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    if euid != user.uid || egid != user.gid {
        return Err(CollectorError::PrivilegeDrop(format!(
            "privilege drop verification failed: euid={euid} egid={egid}"
        )));
    }
    tracing::info!(uid = user.uid, gid = user.gid, "dropped privileges");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use syscall_core::clock;

    fn request(command: &[&str], redact: bool) -> RecordRequest {
        RecordRequest {
            database_path: PathBuf::from("/tmp/test.db"),
            command: command.iter().map(OsString::from).collect(),
            scope: RecordingScope::TargetTree,
            redact_arguments: redact,
            session_id: None,
        }
    }

    #[test]
    fn validates_empty_command() {
        let req = request(&[], false);
        assert!(matches!(
            validate_request(&req),
            Err(CollectorError::InvalidRequest(_))
        ));
    }

    #[test]
    fn redacts_arguments_on_request() {
        let req = request(&["/usr/bin/curl", "secret"], true);
        let (command, arguments) = session_command(&req);
        assert_eq!(command, "/usr/bin/curl");
        assert_eq!(arguments, vec!["<redacted>"]);
    }

    #[test]
    fn keeps_arguments_by_default() {
        let req = request(&["/usr/bin/sleep", "5"], false);
        let (_, arguments) = session_command(&req);
        assert_eq!(arguments, vec!["5"]);
    }

    #[test]
    fn identifies_collector_self_samples_by_any_pid_field() {
        let mut raw = DecodedEvent {
            event_type: EventType::ProcessExec,
            monotonic_ns: 1,
            pid: 4242,
            tgid: 4242,
            ns_tgid: 4242,
            uid: 1000,
            gid: 1000,
            comm: "syscall".to_owned(),
            payload: DecodedPayload::Exec {
                old_pid: 0,
                filename: "/bin/true".to_owned(),
            },
            wire_schema_version: 3,
        };
        assert!(is_collector_self(&raw, 4242));

        raw.pid = 5000;
        assert!(is_collector_self(&raw, 4242), "raw tgid still matches");

        raw.tgid = 5001;
        assert!(is_collector_self(&raw, 4242), "ns_tgid still matches");

        raw.ns_tgid = 5002;
        assert!(!is_collector_self(&raw, 4242));
        assert!(is_collector_self(&raw, 5002));
    }

    #[test]
    fn normalizes_comm_to_kernel_limit() {
        assert_eq!(normalize_comm("", None), "unknown");
        assert_eq!(normalize_comm("", Some("fallback")), "fallback");
        assert!(normalize_comm(&"x".repeat(64), None).len() < COMM_LEN);
    }

    #[test]
    fn builds_a_real_exec_event_for_this_process() {
        let pid = std::process::id() as i32;
        let info = procfs::read(pid).unwrap();
        let mut scope = ScopeTracker::new(RecordingScope::TargetTree, "boot");
        scope.register_root(pid, Some(info.ppid), info.start_time_ticks, &info.comm, 1);
        let raw = DecodedEvent {
            event_type: EventType::ProcessExec,
            monotonic_ns: 1234,
            pid,
            tgid: pid,
            ns_tgid: 0,
            uid: info.uid,
            gid: info.gid,
            comm: info.comm.clone(),
            payload: DecodedPayload::Exec {
                old_pid: 1,
                filename: "/usr/bin/test".to_owned(),
            },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(mut events) = build_event(
            &raw,
            &mut scope,
            &mut HashMap::new(),
            "s-test",
            "boot",
            clock::wall_offset_ns().unwrap(),
        ) else {
            panic!("expected event to be included");
        };
        let event = events.pop().expect("expected one event");
        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(event.pid, pid);
        assert_eq!(
            event.process_instance_id,
            format!("boot:{pid}:{}", info.start_time_ticks.unwrap())
        );
    }

    #[test]
    fn filters_thread_exit_events() {
        let raw = DecodedEvent {
            event_type: EventType::ProcessExit,
            monotonic_ns: 1,
            pid: 101,
            tgid: 100,
            ns_tgid: 0,
            uid: 1000,
            gid: 1000,
            comm: "thread".to_owned(),
            payload: DecodedPayload::Exit { exit_priority: 120 },
            wire_schema_version: 2,
        };
        let mut scope = ScopeTracker::new(RecordingScope::System, "boot");
        assert!(matches!(
            build_event(&raw, &mut scope, &mut HashMap::new(), "s", "boot", 0),
            BuildOutcome::Rejected(RejectReason::ThreadContext)
        ));
    }

    #[test]
    fn cross_namespace_exec_is_attributed_via_ns_tgid() {
        // Regression for the privileged WSL2 failure where BPF reported exec
        // tgid 61527 (BPF/global ID space) while the root was registered as
        // observer-ns PID 48180; build_event must pass ns_tgid to scope so the
        // alias is learned and the root exec is included (not OutOfScope).
        let mut scope = ScopeTracker::new(RecordingScope::TargetTree, "boot");
        scope.register_root(48180, Some(48179), Some(100), "syscall", 1);
        let raw = DecodedEvent {
            event_type: EventType::ProcessExec,
            monotonic_ns: 1234,
            pid: 61527,
            tgid: 61527,
            ns_tgid: 48180,
            uid: 1000,
            gid: 1000,
            comm: "sh".to_owned(),
            payload: DecodedPayload::Exec {
                old_pid: 61527,
                filename: "/bin/sh".to_owned(),
            },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(mut events) =
            build_event(&raw, &mut scope, &mut HashMap::new(), "s-test", "boot", 0)
        else {
            panic!("expected cross-namespace root exec to be included via ns_tgid correlation");
        };
        let event = events.pop().expect("expected one event");
        assert_eq!(event.event_type, EventType::ProcessExec);
        assert_eq!(event.comm, "sh");
        // Canonical/observer-visible identity must be consistent (not raw BPF 61527).
        assert_eq!(event.pid, 48180);
        assert!(event.process_instance_id.starts_with("boot:48180:"));
        // Subsequent events carrying the BPF tgid must resolve via the learned alias.
        assert!(scope.get(61527).is_some() || scope.get(48180).is_some());
    }

    #[test]
    fn fork_buffered_until_exec_preserves_stable_canonical_identity() {
        // Models cross-namespace fork(ns_tgid=0, bpf child 64570) followed by
        // child exec(ns_tgid=51221): fork must be buffered and flushed with the
        // same canonical process_instance_id as exec.
        let mut scope = ScopeTracker::new(RecordingScope::TargetTree, "boot");
        scope.register_root(48180, Some(48179), Some(100), "syscall", 1);
        // Root exec learns alias 61527 -> 48180.
        let root_exec = DecodedEvent {
            event_type: EventType::ProcessExec,
            monotonic_ns: 1,
            pid: 61527,
            tgid: 61527,
            ns_tgid: 48180,
            uid: 1000,
            gid: 1000,
            comm: "sh".to_owned(),
            payload: DecodedPayload::Exec {
                old_pid: 61527,
                filename: "/bin/sh".to_owned(),
            },
            wire_schema_version: 2,
        };
        let mut buf = HashMap::new();
        assert!(matches!(
            build_event(&root_exec, &mut scope, &mut buf, "s", "boot", 0),
            BuildOutcome::Included(_)
        ));

        let fork = DecodedEvent {
            event_type: EventType::ProcessFork,
            monotonic_ns: 2,
            pid: 64570,
            tgid: 64570,
            ns_tgid: 0,
            uid: 1000,
            gid: 1000,
            comm: "sleep".to_owned(),
            payload: DecodedPayload::Fork {
                parent_pid: 61527,
                child_pid: 64570,
                parent_comm: "sh".to_owned(),
                child_comm: "sleep".to_owned(),
            },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(events) =
            build_event(&fork, &mut scope, &mut buf, "s", "boot", 0)
        else {
            panic!()
        };
        assert!(
            events.is_empty(),
            "fork without canonical identity must be buffered, not fabricated"
        );
        assert!(buf.contains_key(&64570));

        let child_exec = DecodedEvent {
            event_type: EventType::ProcessExec,
            monotonic_ns: 3,
            pid: 64570,
            tgid: 64570,
            ns_tgid: 51221,
            uid: 1000,
            gid: 1000,
            comm: "sleep".to_owned(),
            payload: DecodedPayload::Exec {
                old_pid: 64570,
                filename: "/bin/sleep".to_owned(),
            },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(events) =
            build_event(&child_exec, &mut scope, &mut buf, "s", "boot", 0)
        else {
            panic!()
        };
        assert_eq!(events.len(), 2, "buffered fork + exec");
        assert_eq!(events[0].event_type, EventType::ProcessFork);
        assert_eq!(events[1].event_type, EventType::ProcessExec);
        assert_eq!(events[0].pid, 51221);
        assert_eq!(events[1].pid, 51221);
        assert_eq!(events[0].process_instance_id, events[1].process_instance_id);
        assert!(!buf.contains_key(&64570));
    }

    #[test]
    fn fork_exec_exit_share_stable_process_instance() {
        let mut scope = ScopeTracker::new(RecordingScope::TargetTree, "boot");
        scope.register_root(100, Some(1), Some(5), "sh", 1);
        let mut buf = HashMap::new();
        let fork = DecodedEvent {
            event_type: EventType::ProcessFork,
            monotonic_ns: 2,
            pid: 64570,
            tgid: 64570,
            ns_tgid: 0,
            uid: 1000,
            gid: 1000,
            comm: "true".to_owned(),
            payload: DecodedPayload::Fork {
                parent_pid: 100,
                child_pid: 64570,
                parent_comm: "sh".to_owned(),
                child_comm: "true".to_owned(),
            },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(e) = build_event(&fork, &mut scope, &mut buf, "s", "boot", 0)
        else {
            panic!()
        };
        assert!(e.is_empty());
        let exec = DecodedEvent {
            event_type: EventType::ProcessExec,
            monotonic_ns: 3,
            pid: 64570,
            tgid: 64570,
            ns_tgid: 51222,
            uid: 1000,
            gid: 1000,
            comm: "true".to_owned(),
            payload: DecodedPayload::Exec {
                old_pid: 64570,
                filename: "/bin/true".to_owned(),
            },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(events) =
            build_event(&exec, &mut scope, &mut buf, "s", "boot", 0)
        else {
            panic!()
        };
        assert_eq!(events.len(), 2);
        let iid = events[1].process_instance_id.clone();
        assert_eq!(events[0].process_instance_id, iid);
        let exit = DecodedEvent {
            event_type: EventType::ProcessExit,
            monotonic_ns: 4,
            pid: 64570,
            tgid: 64570,
            ns_tgid: 51222,
            uid: 1000,
            gid: 1000,
            comm: "true".to_owned(),
            payload: DecodedPayload::Exit { exit_priority: 0 },
            wire_schema_version: 2,
        };
        let BuildOutcome::Included(events) =
            build_event(&exit, &mut scope, &mut buf, "s", "boot", 0)
        else {
            panic!()
        };
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::ProcessExit);
        assert_eq!(events[0].pid, 51222);
        assert_eq!(events[0].process_instance_id, iid);
    }
    #[test]
    fn file_activity_is_attributed_in_system_scope() {
        let pid = std::process::id() as i32;
        let info = procfs::read(pid).unwrap();
        let mut scope = ScopeTracker::new(RecordingScope::System, "boot");
        let raw = DecodedEvent {
            event_type: EventType::FileOpen,
            monotonic_ns: 2000,
            pid,
            tgid: pid,
            ns_tgid: 0,
            uid: info.uid,
            gid: info.gid,
            comm: info.comm.clone(),
            payload: DecodedPayload::FileOpen {
                path: "/etc/hosts".to_owned(),
                path_is_absolute: true,
                path_truncated: false,
                dirfd: -100,
                flags: 0,
                result: 4,
            },
            wire_schema_version: 3,
        };
        let BuildOutcome::Included(events) = build_event(
            &raw,
            &mut scope,
            &mut HashMap::new(),
            "s-activity",
            "boot",
            0,
        ) else {
            panic!("expected file activity to be included");
        };
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.event_type, EventType::FileOpen);
        assert_eq!(event.pid, pid);
        assert_eq!(
            event
                .provenance
                .as_ref()
                .unwrap()
                .source_tracepoint
                .as_deref(),
            Some("syscalls/sys_exit_openat")
        );
        let EventPayload::FileOpen {
            path,
            result,
            success,
            errno,
            ..
        } = &event.payload
        else {
            panic!("expected file payload");
        };
        assert_eq!(path, "/etc/hosts");
        assert_eq!(*result, 4);
        assert!(*success);
        assert_eq!(*errno, None);
    }

    #[test]
    fn network_activity_respects_target_tree_scope() {
        let pid = std::process::id() as i32;
        let info = procfs::read(pid).unwrap();
        let mut scope = ScopeTracker::new(RecordingScope::TargetTree, "boot");
        scope.register_root(pid, Some(info.ppid), info.start_time_ticks, &info.comm, 1);
        let mut raw = DecodedEvent {
            event_type: EventType::NetworkConnect,
            monotonic_ns: 3000,
            pid,
            tgid: pid,
            ns_tgid: 0,
            uid: info.uid,
            gid: info.gid,
            comm: info.comm.clone(),
            payload: DecodedPayload::NetworkConnect {
                family: syscall_core::AddressFamily::Ipv4,
                source_address: None,
                source_port: None,
                destination_address: "192.0.2.1".to_owned(),
                destination_port: 443,
                result: -111,
            },
            wire_schema_version: 3,
        };
        let BuildOutcome::Included(events) = build_event(
            &raw,
            &mut scope,
            &mut HashMap::new(),
            "s-activity",
            "boot",
            0,
        ) else {
            panic!("expected root network activity to be included");
        };
        let EventPayload::NetworkConnect {
            result,
            success,
            errno,
            established,
            ..
        } = &events[0].payload
        else {
            panic!("expected network payload");
        };
        assert_eq!(*result, -111);
        assert!(!*success);
        assert_eq!(*errno, Some(111));
        assert!(!*established);

        raw.pid = 999_999;
        raw.tgid = 999_999;
        assert!(matches!(
            build_event(
                &raw,
                &mut scope,
                &mut HashMap::new(),
                "s-activity",
                "boot",
                0,
            ),
            BuildOutcome::Rejected(RejectReason::OutOfScope)
        ));
    }
}
