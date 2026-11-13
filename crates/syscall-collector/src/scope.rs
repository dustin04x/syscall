//! Target-tree attribution.
//!
//! Scheduler tracepoints are system-wide. Mission 01 therefore attaches
//! system-wide and filters in userspace: the root PID is registered right after
//! the target is spawned, descendants are admitted when a tracked parent is
//! observed, and `/proc` ancestry is used as a fallback for events that arrive
//! out of order or whose fork event was lost.
//!
//! This is a logical scope, not a kernel-side PID filter. The limitation is
//! recorded in session metadata and documented in docs/ARCHITECTURE.md.

use std::collections::HashMap;

use syscall_core::ids::process_instance_id;
use syscall_core::RecordingScope;

use crate::procfs::{self, ProcInfo};

const MAX_ANCESTRY_DEPTH: usize = 64;
/// Hard cap on live tracked processes. A fork bomb must not grow userspace
/// memory without bound; events beyond the cap are reported as filtered.
pub const MAX_TRACKED_PROCESSES: usize = 65_536;
/// Alias entries are normally a handful per process, but namespace churn must
/// not grow this map without bound.
pub const MAX_ALIASES: usize = MAX_TRACKED_PROCESSES * 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedProcess {
    /// Canonical TGID: observer-visible PID when namespace correlation is
    /// established, otherwise a provisional/raw ID with `provisional` set.
    pub tgid: i32,
    pub ppid: Option<i32>,
    pub start_time_ticks: Option<u64>,
    pub process_instance_id: String,
    pub comm: String,
    /// Raw BPF-observed TGID when different from canonical (cross-namespace).
    pub raw_tgid: Option<i32>,
    /// True when canonical observer-visible identity is not yet established;
    /// the process is tracked for attribution but must not be persisted with a
    /// fabricated canonical identity.
    pub provisional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    Included(TrackedProcess),
    OutOfScope,
}

pub type Lookup = Box<dyn Fn(i32) -> Option<ProcInfo>>;

pub struct ScopeTracker {
    mode: RecordingScope,
    boot_id: String,
    /// Canonical root PID (BPF/kernel-visible identity when aliases exist).
    root_pid: Option<i32>,
    root_exited: bool,
    tracked: HashMap<i32, TrackedProcess>,
    /// Namespace/identity aliases -> canonical tracked TGID.
    aliases: HashMap<i32, i32>,
    lookup: Lookup,
}

impl ScopeTracker {
    pub fn new(mode: RecordingScope, boot_id: impl Into<String>) -> Self {
        Self::with_lookup(mode, boot_id, Box::new(procfs::read))
    }

    pub fn with_lookup(mode: RecordingScope, boot_id: impl Into<String>, lookup: Lookup) -> Self {
        let boot_id = {
            let value = boot_id.into();
            if value.trim().is_empty() {
                "unknown-boot".to_owned()
            } else {
                value
            }
        };
        Self {
            mode,
            boot_id,
            root_pid: None,
            root_exited: false,
            tracked: HashMap::new(),
            aliases: HashMap::new(),
            lookup,
        }
    }

    pub fn mode(&self) -> RecordingScope {
        self.mode
    }

    pub fn root_pid(&self) -> Option<i32> {
        self.root_pid
    }

    pub fn root_exited(&self) -> bool {
        self.root_exited
    }

    pub fn tracked_count(&self) -> usize {
        self.tracked.len()
    }

    /// Register PID namespace aliases for a canonical tracked TGID.
    pub fn register_aliases(&mut self, canonical: i32, alias_pids: &[i32]) {
        if canonical <= 0 {
            return;
        }
        if self.aliases.len() >= MAX_ALIASES {
            let stale: Vec<i32> = self
                .aliases
                .iter()
                .filter(|(_, mapped)| {
                    !self.tracked.contains_key(*mapped) && self.root_pid != Some(**mapped)
                })
                .map(|(alias, _)| *alias)
                .collect();
            for alias in stale {
                self.aliases.remove(&alias);
            }
        }
        if self.aliases.len() >= MAX_ALIASES {
            return;
        }
        self.aliases.insert(canonical, canonical);
        for &alias in alias_pids {
            if alias > 0 && self.aliases.len() < MAX_ALIASES {
                self.aliases.insert(alias, canonical);
            }
        }
    }

    pub(crate) fn canonical_pid(&self, pid: i32) -> i32 {
        if pid <= 0 {
            return pid;
        }
        self.aliases.get(&pid).copied().unwrap_or(pid)
    }

    /// Register the directly spawned target. This is the only process admitted
    /// without a tracked ancestor.
    pub fn register_root(
        &mut self,
        tgid: i32,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) -> TrackedProcess {
        self.register_root_with_aliases(
            tgid,
            &[],
            ppid,
            start_time_ticks,
            comm,
            fallback_monotonic_ns,
        )
    }

    /// Register the spawned root with PID namespace aliases. `canonical_tgid`
    /// should prefer the BPF/kernel-visible identity (e.g. initial `NSpid`)
    /// when known; `aliases` may include all `NSpid`/`NStgid` values.
    pub fn register_root_with_aliases(
        &mut self,
        canonical_tgid: i32,
        aliases: &[i32],
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) -> TrackedProcess {
        self.root_pid = Some(canonical_tgid);
        self.root_exited = false;
        self.register_aliases(canonical_tgid, aliases);
        self.insert_or_replace(
            canonical_tgid,
            ppid,
            start_time_ticks,
            comm,
            fallback_monotonic_ns,
        )
    }

    /// Decide whether a process instance belongs to this recording.
    pub fn resolve(
        &mut self,
        tgid: i32,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) -> Attribution {
        self.resolve_observed(
            tgid,
            None,
            ppid,
            None,
            start_time_ticks,
            comm,
            fallback_monotonic_ns,
        )
    }

    /// Resolve attribution for an observed event, optionally carrying a
    /// PID-namespace-correlated TGID (`ns_tgid`, e.g. BPF
    /// `bpf_get_ns_current_pid_tgid` in the observer namespace). When
    /// `ns_tgid` identifies an already-tracked process, `tgid` is treated as an
    /// alias of that process so events remain attributable across PID
    /// namespace ID spaces. This does not admit untracked processes.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_observed(
        &mut self,
        tgid: i32,
        ns_tgid: Option<i32>,
        ppid: Option<i32>,
        ns_ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) -> Attribution {
        if tgid <= 0 {
            return Attribution::OutOfScope;
        }
        // If observer-namespace TGID (ns_tgid) is known and the raw BPF TGID is
        // tracked provisionally (fork arrived before identity correlation), upgrade
        // to canonical observer-visible identity so fork/exec/exit share one stable
        // process instance. This is the key cross-namespace correlation path.
        if let Some(ns) = ns_tgid.filter(|v| *v > 0) {
            let ns_canonical = self.canonical_pid(ns);
            let raw_canonical = self.canonical_pid(tgid);
            let ns_tracked =
                self.tracked.contains_key(&ns_canonical) || self.root_pid == Some(ns_canonical);
            let raw_provisional = self
                .tracked
                .get(&raw_canonical)
                .is_some_and(|p| p.provisional);
            if ns_tracked {
                tracing::debug!(
                    phase = "scope",
                    bpf_tgid = tgid,
                    ns_tgid = ns,
                    canonical_tgid = ns_canonical,
                    root_pid = ?self.root_pid,
                    "learned PID namespace alias for tracked process"
                );
                self.register_aliases(ns_canonical, &[tgid, ns, raw_canonical]);
            } else if raw_provisional && raw_canonical != ns_canonical {
                self.upgrade_provisional_to_canonical(
                    raw_canonical,
                    ns_canonical,
                    ppid.map(|p| self.canonical_pid(p))
                        .or(ns_ppid.map(|p| self.canonical_pid(p))),
                    start_time_ticks,
                    comm,
                    fallback_monotonic_ns,
                );
                self.register_aliases(ns_canonical, &[tgid, ns, raw_canonical]);
            }
        }
        if let Some(ns_p) = ns_ppid.filter(|v| *v > 0) {
            let ns_canonical = self.canonical_pid(ns_p);
            if self.tracked.contains_key(&ns_canonical) || self.root_pid == Some(ns_canonical) {
                if let Some(p) = ppid {
                    self.register_aliases(ns_canonical, &[p, ns_p]);
                }
            }
        }
        let tgid = self.canonical_pid(tgid);
        let ppid = ppid.map(|p| self.canonical_pid(p));
        if self.tracked.len() >= MAX_TRACKED_PROCESSES
            && !self.tracked.contains_key(&tgid)
            && self.root_pid != Some(tgid)
        {
            return Attribution::OutOfScope;
        }

        if self.mode == RecordingScope::System {
            return Attribution::Included(self.insert_or_replace(
                tgid,
                ppid,
                start_time_ticks,
                comm,
                fallback_monotonic_ns,
            ));
        }

        // If the caller's start-time reading conflicts with what we know about
        // the root, confirm with a fresh /proc read before destroying the target
        // tree. A stale or inconsistent reading must not permanently filter the
        // real target process (that produced "10 filtered, 0 persisted" in the
        // first privileged WSL2 run).
        let mut start_time_ticks = start_time_ticks;
        let mut ppid = ppid;
        if self.root_pid == Some(tgid) && !self.root_exited {
            if let Some(existing) = self.tracked.get(&tgid) {
                if is_pid_reuse(existing.start_time_ticks, start_time_ticks) {
                    if let Some(confirm) = (self.lookup)(tgid) {
                        let confirmed = confirm.start_time_ticks;
                        ppid = ppid.or(Some(confirm.ppid));
                        if !comm.trim().is_empty() {
                            // keep caller comm precedence below via insert
                        }
                        if is_pid_reuse(existing.start_time_ticks, confirmed) {
                            // Confirmed: the root PID was reused by a different
                            // instance and the exit event was likely lost.
                            start_time_ticks = confirmed;
                            self.root_exited = true;
                            self.tracked.remove(&tgid);
                        } else {
                            // Caller reading was inconsistent; keep the root.
                            start_time_ticks = existing.start_time_ticks.or(confirmed);
                            return Attribution::Included(self.insert_or_replace(
                                tgid,
                                ppid,
                                start_time_ticks,
                                comm,
                                fallback_monotonic_ns,
                            ));
                        }
                    } else {
                        // Cannot confirm reuse (process may have exited and /proc
                        // vanished). Keep the existing root identity so a late
                        // exit/exec event can still be attributed; the exit path
                        // will clean up tracking.
                        start_time_ticks = existing.start_time_ticks;
                        return Attribution::Included(self.insert_or_replace(
                            tgid,
                            ppid,
                            start_time_ticks,
                            comm,
                            fallback_monotonic_ns,
                        ));
                    }
                } else {
                    return Attribution::Included(self.insert_or_replace(
                        tgid,
                        ppid,
                        start_time_ticks,
                        comm,
                        fallback_monotonic_ns,
                    ));
                }
            } else {
                return Attribution::Included(self.insert_or_replace(
                    tgid,
                    ppid,
                    start_time_ticks,
                    comm,
                    fallback_monotonic_ns,
                ));
            }
        }

        if let Some(existing) = self.tracked.get(&tgid).cloned() {
            if !is_pid_reuse(existing.start_time_ticks, start_time_ticks) {
                // Refresh missing metadata without changing the instance.
                return Attribution::Included(self.insert_or_replace(
                    tgid,
                    ppid,
                    start_time_ticks,
                    comm,
                    fallback_monotonic_ns,
                ));
            }
            // Possible PID reuse for a non-root tracked process. Confirm before
            // removing so a transient bad reading does not orphan descendants.
            if let Some(confirm) = (self.lookup)(tgid) {
                let confirmed = confirm.start_time_ticks;
                ppid = ppid.or(Some(confirm.ppid));
                if is_pid_reuse(existing.start_time_ticks, confirmed) {
                    self.tracked.remove(&tgid);
                    start_time_ticks = confirmed;
                } else {
                    start_time_ticks = existing.start_time_ticks.or(confirmed);
                    return Attribution::Included(self.insert_or_replace(
                        tgid,
                        ppid,
                        start_time_ticks,
                        comm,
                        fallback_monotonic_ns,
                    ));
                }
            } else {
                self.tracked.remove(&tgid);
            }
        }

        // Accept direct children of the root even if root registration state was
        // disturbed, as long as the root has not been confirmed exited/reused.
        if !self.root_exited && self.root_pid.is_some() && ppid == self.root_pid {
            return Attribution::Included(self.insert_or_replace(
                tgid,
                ppid,
                start_time_ticks,
                comm,
                fallback_monotonic_ns,
            ));
        }

        if self.has_tracked_ancestor(ppid) {
            Attribution::Included(self.insert_or_replace(
                tgid,
                ppid,
                start_time_ticks,
                comm,
                fallback_monotonic_ns,
            ))
        } else {
            Attribution::OutOfScope
        }
    }

    /// Record the exit of a tracked process.
    pub fn mark_exited(&mut self, tgid: i32) {
        let canonical = self.canonical_pid(tgid);
        if self.root_pid == Some(canonical) || self.root_pid == Some(tgid) {
            self.root_exited = true;
        }
        self.tracked.remove(&canonical);
        self.tracked.remove(&tgid);
        self.aliases
            .retain(|_, mapped| *mapped != canonical && *mapped != tgid);
    }

    pub fn get(&self, tgid: i32) -> Option<&TrackedProcess> {
        let canonical = self.canonical_pid(tgid);
        self.tracked
            .get(&canonical)
            .or_else(|| self.tracked.get(&tgid))
    }

    /// Track a forked child whose observer-visible canonical identity is not yet
    /// known (e.g. cross-namespace fork with ns_tgid=0). The process is admitted
    /// to scope via tracked parent lineage, but marked provisional so callers do
    /// not persist a fabricated canonical identity.
    #[allow(clippy::too_many_arguments)]
    pub fn register_provisional(
        &mut self,
        raw_tgid: i32,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) -> Attribution {
        if raw_tgid <= 0 {
            return Attribution::OutOfScope;
        }
        if self.tracked.len() >= MAX_TRACKED_PROCESSES && !self.tracked.contains_key(&raw_tgid) {
            return Attribution::OutOfScope;
        }
        let ppid = ppid.map(|p| self.canonical_pid(p));
        if self.mode == RecordingScope::System
            || self.root_pid == Some(raw_tgid)
            || ppid == self.root_pid
            || self.has_tracked_ancestor(ppid)
        {
            Attribution::Included(self.insert_or_replace_inner(
                raw_tgid,
                ppid,
                start_time_ticks,
                comm,
                fallback_monotonic_ns,
                Some(raw_tgid),
                true,
            ))
        } else {
            Attribution::OutOfScope
        }
    }

    pub fn is_provisional(&self, tgid: i32) -> bool {
        let canonical = self.canonical_pid(tgid);
        self.tracked.get(&canonical).is_some_and(|p| p.provisional)
    }

    #[allow(clippy::too_many_arguments)]
    fn upgrade_provisional_to_canonical(
        &mut self,
        raw_canonical: i32,
        observer_canonical: i32,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) {
        let Some(previous) = self.tracked.remove(&raw_canonical) else {
            return;
        };
        tracing::debug!(
            phase = "scope",
            raw_bpf_tgid = raw_canonical,
            canonical_pid = observer_canonical,
            old_process_instance_id = %previous.process_instance_id,
            "upgrading provisional process to canonical observer-visible identity"
        );
        let start_time_ticks = start_time_ticks.or(previous.start_time_ticks);
        let ppid = ppid.or(previous.ppid);
        let comm = if comm.trim().is_empty() || comm == "unknown" {
            &previous.comm
        } else {
            comm
        };
        let process_instance_id = process_instance_id(
            &self.boot_id,
            observer_canonical,
            start_time_ticks,
            fallback_monotonic_ns,
        );
        let tracked = TrackedProcess {
            tgid: observer_canonical,
            ppid,
            start_time_ticks,
            process_instance_id,
            comm: comm.to_owned(),
            raw_tgid: Some(previous.raw_tgid.unwrap_or(raw_canonical)),
            provisional: false,
        };
        if self.root_pid == Some(raw_canonical) {
            self.root_pid = Some(observer_canonical);
        }
        self.register_aliases(observer_canonical, &[raw_canonical, observer_canonical]);
        self.tracked.insert(observer_canonical, tracked);
    }

    fn insert_or_replace(
        &mut self,
        tgid: i32,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
    ) -> TrackedProcess {
        self.insert_or_replace_inner(
            tgid,
            ppid,
            start_time_ticks,
            comm,
            fallback_monotonic_ns,
            None,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_or_replace_inner(
        &mut self,
        tgid: i32,
        ppid: Option<i32>,
        start_time_ticks: Option<u64>,
        comm: &str,
        fallback_monotonic_ns: u64,
        raw_tgid: Option<i32>,
        provisional: bool,
    ) -> TrackedProcess {
        let existing = self.tracked.get(&tgid).cloned();
        let start_time_ticks = match (
            existing.as_ref().and_then(|p| p.start_time_ticks),
            start_time_ticks,
        ) {
            (Some(known), Some(fresh)) if is_pid_reuse(Some(known), Some(fresh)) => Some(fresh),
            (Some(known), _) => Some(known),
            (None, fresh) => fresh,
        };
        let raw_tgid = raw_tgid.or_else(|| existing.as_ref().and_then(|p| p.raw_tgid));
        let provisional = if existing.as_ref().is_some_and(|p| !p.provisional) {
            false
        } else {
            provisional || existing.as_ref().is_some_and(|p| p.provisional)
        };
        let process_instance_id = match &existing {
            // Without a start time, keep the original fallback identity so the
            // same process does not appear as multiple instances per event.
            Some(previous)
                if previous.start_time_ticks.is_none()
                    && start_time_ticks.is_none()
                    && previous.tgid == tgid =>
            {
                previous.process_instance_id.clone()
            }
            // If already canonical (not provisional), keep stable identity unless
            // start_time proves PID reuse.
            Some(previous)
                if !previous.provisional
                    && previous.tgid == tgid
                    && !is_pid_reuse(previous.start_time_ticks, start_time_ticks) =>
            {
                previous.process_instance_id.clone()
            }
            _ => process_instance_id(&self.boot_id, tgid, start_time_ticks, fallback_monotonic_ns),
        };
        let tracked = TrackedProcess {
            tgid,
            ppid,
            start_time_ticks,
            process_instance_id,
            comm: comm.to_owned(),
            raw_tgid,
            provisional,
        };
        self.tracked.insert(tgid, tracked.clone());
        tracked
    }

    fn has_tracked_ancestor(&self, mut ppid: Option<i32>) -> bool {
        let mut seen = 0usize;
        let mut last = None;
        while let Some(pid) = ppid {
            let pid = self.canonical_pid(pid);
            if pid <= 0 || last == Some(pid) || seen >= MAX_ANCESTRY_DEPTH {
                return false;
            }
            if self.tracked.contains_key(&pid) || (!self.root_exited && self.root_pid == Some(pid))
            {
                return true;
            }
            seen += 1;
            last = Some(pid);
            ppid = (self.lookup)(pid)
                .map(|info| info.ppid)
                .map(|p| self.canonical_pid(p));
        }
        false
    }
}

fn is_pid_reuse(existing: Option<u64>, fresh: Option<u64>) -> bool {
    match (existing, fresh) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(pid: i32, ppid: i32, start: u64) -> ProcInfo {
        ProcInfo {
            pid,
            tgid: pid,
            ppid,
            uid: 1000,
            gid: 1000,
            start_time_ticks: Some(start),
            comm: format!("p{pid}"),
            nspid: vec![pid],
            nstgid: vec![pid],
        }
    }

    fn tracker(mode: RecordingScope, entries: Vec<ProcInfo>) -> ScopeTracker {
        let map: HashMap<i32, ProcInfo> = entries.into_iter().map(|p| (p.pid, p)).collect();
        ScopeTracker::with_lookup(mode, "boot", Box::new(move |pid| map.get(&pid).cloned()))
    }

    #[test]
    fn target_tree_admits_root_and_direct_child() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "child", 11),
            Attribution::Included(_)
        ));
        assert_eq!(
            scope.resolve(200, Some(1), Some(7), "unrelated", 12),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn unknown_child_is_admitted_through_proc_ancestry() {
        // Simulate a lost fork event: 101's parent is the tracked root.
        let entries = vec![info(101, 100, 6), info(102, 101, 7)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        assert!(matches!(
            scope.resolve(102, Some(101), Some(7), "grandchild", 12),
            Attribution::Included(_)
        ));
    }

    #[test]
    fn unrelated_process_is_not_admitted() {
        let entries = vec![info(200, 1, 7)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        assert_eq!(
            scope.resolve(200, Some(1), Some(7), "unrelated", 12),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn pid_reuse_is_not_attributed_without_lineage() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "child", 11),
            Attribution::Included(_)
        ));
        // The child exited, and an unrelated process reused PID 101.
        scope.mark_exited(101);
        assert_eq!(
            scope.resolve(101, Some(1), Some(999), "reused", 12),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn system_scope_admits_everything() {
        let mut scope = tracker(RecordingScope::System, vec![]);
        assert!(matches!(
            scope.resolve(200, Some(1), Some(7), "unrelated", 12),
            Attribution::Included(_)
        ));
        assert_eq!(scope.tracked_count(), 1);
    }

    #[test]
    fn root_exit_is_recorded() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        scope.mark_exited(100);
        assert!(scope.root_exited());
        assert_eq!(scope.tracked_count(), 0);
    }

    #[test]
    fn reused_root_pid_is_not_attributed_after_root_exit() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        scope.mark_exited(100);
        assert_eq!(
            scope.resolve(100, Some(1), Some(999), "reused", 12),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn reused_root_pid_is_detected_even_if_exit_event_was_lost() {
        // Exit event was lost; /proc now shows a different process instance on
        // the same PID. Lookup confirmation must prevent attributing it.
        let entries = vec![info(100, 1, 999)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        assert_eq!(
            scope.resolve(100, Some(1), Some(999), "reused", 12),
            Attribution::OutOfScope
        );
        assert!(scope.root_exited());
    }

    #[test]
    fn unconfirmed_root_start_time_conflict_does_not_nuke_target_tree() {
        // If /proc is unavailable for confirmation, keep root tracking so the
        // real target session is not collapsed to "all filtered".
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        let result = scope.resolve(100, Some(1), Some(999), "target", 12);
        assert!(matches!(result, Attribution::Included(_)));
        assert!(!scope.root_exited());
    }

    #[test]
    fn tracked_processes_are_capped() {
        let mut scope = tracker(RecordingScope::System, vec![]);
        for pid in 1..=MAX_TRACKED_PROCESSES {
            let attribution = scope.resolve(pid as i32, Some(1), Some(pid as u64), "p", 1);
            assert!(matches!(attribution, Attribution::Included(_)));
        }
        assert_eq!(scope.tracked_count(), MAX_TRACKED_PROCESSES);
        assert_eq!(
            scope.resolve(
                (MAX_TRACKED_PROCESSES + 1) as i32,
                Some(1),
                Some(1),
                "overflow",
                1
            ),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn process_instance_id_is_boot_scoped() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        let root = scope.register_root(100, Some(1), Some(5), "target", 10);
        assert_eq!(root.process_instance_id, "boot:100:5");
    }

    #[test]
    fn missing_start_time_fallback_identity_is_stable() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        let Attribution::Included(first) = scope.resolve(101, Some(100), None, "child", 111) else {
            panic!("child should be included");
        };
        let Attribution::Included(second) = scope.resolve(101, Some(100), None, "child", 222)
        else {
            panic!("child should remain included");
        };
        assert_eq!(first.process_instance_id, "boot:101:unknown-111");
        assert_eq!(first.process_instance_id, second.process_instance_id);
    }

    #[test]
    fn root_exec_is_not_filtered_by_inconsistent_caller_start_time() {
        // Regression: first privileged WSL2 run filtered all 10 events.
        // A stale/inconsistent start-time reading must not destroy root tracking.
        let entries = vec![info(100, 1, 5)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "sh", 10);
        let result = scope.resolve(100, Some(1), Some(999), "sh", 11);
        assert!(
            matches!(result, Attribution::Included(_)),
            "root must remain attributed when /proc confirms the same instance"
        );
        assert!(!scope.root_exited());
        assert!(scope.get(100).is_some());
    }

    #[test]
    fn confirmed_root_reuse_is_filtered() {
        // If /proc confirms a different start time, the root instance is gone.
        let entries = vec![info(100, 1, 999)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "target", 10);
        assert_eq!(
            scope.resolve(100, Some(1), Some(999), "reused", 12),
            Attribution::OutOfScope
        );
        assert!(scope.root_exited());
    }

    #[test]
    fn target_tree_full_lifecycle_with_synthetic_events() {
        // Models /bin/sh spawning /bin/sleep: exec(root), fork, exec(child),
        // exit(child), exit(root). Uses a synthetic /proc lookup.
        let entries = vec![info(100, 1, 5), info(101, 100, 6)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "sh", 10);

        // Root exec.
        assert!(matches!(
            scope.resolve(100, Some(1), Some(5), "sh", 11),
            Attribution::Included(_)
        ));
        // Fork creates child under tracked root.
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "sleep", 12),
            Attribution::Included(_)
        ));
        // Child exec arrives after fork; child is already tracked.
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "sleep", 13),
            Attribution::Included(_)
        ));
        // Child exits.
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "sleep", 14),
            Attribution::Included(_)
        ));
        scope.mark_exited(101);
        // Root exits.
        assert!(matches!(
            scope.resolve(100, Some(1), Some(5), "sh", 15),
            Attribution::Included(_)
        ));
        scope.mark_exited(100);
        assert!(scope.root_exited());
        // Unrelated process remains filtered.
        assert_eq!(
            scope.resolve(200, Some(1), Some(7), "sshd", 16),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn child_exec_before_fork_is_admitted_via_ancestry() {
        // Event ordering race: child exec is seen before fork registration.
        let entries = vec![info(100, 1, 5), info(101, 100, 6)];
        let mut scope = tracker(RecordingScope::TargetTree, entries);
        scope.register_root(100, Some(1), Some(5), "sh", 10);
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "true", 11),
            Attribution::Included(_)
        ));
        // Late fork resolves the same tracked child.
        assert!(matches!(
            scope.resolve(101, Some(100), Some(6), "true", 12),
            Attribution::Included(_)
        ));
    }

    #[test]
    fn direct_child_of_root_admitted_even_without_proc_lookup_entry() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "sh", 10);
        assert!(matches!(
            scope.resolve(101, Some(100), None, "child", 11),
            Attribution::Included(_)
        ));
    }

    #[test]
    fn registered_alias_maps_bpf_pid_to_tracked_root() {
        // Synthetic: when a BPF-visible PID is known at registration time, alias
        // lookup attributes events carrying that PID.
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root_with_aliases(35862, &[35862, 49135], Some(35861), Some(5), "sh", 10);
        assert!(matches!(
            scope.resolve(49135, Some(49134), Some(5), "sh", 11),
            Attribution::Included(_)
        ));
        assert!(matches!(
            scope.resolve(49135, Some(49134), Some(5), "sh", 12),
            Attribution::Included(_)
        ));
        assert!(matches!(
            scope.resolve(49136, Some(49135), Some(6), "sleep", 13),
            Attribution::Included(_)
        ));
    }

    #[test]
    fn ns_tgid_learns_alias_for_cross_namespace_bpf_events() {
        // Regression model for WSL2/namespace case: root registered by observer
        // namespace PID (35862, matches BPF ns_tgid from bpf_get_ns_current_pid_tgid),
        // while BPF tracepoint/header pid/tgid may be in a different namespace
        // (49135). exec/exit events carry ns_tgid=35862 -> alias is learned and
        // subsequent lineage is attributed. Fork-of-root may arrive before alias
        // learning if its handler cannot emit child ns_tgid (documented limitation).
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root_with_aliases(35862, &[35862], Some(35861), Some(5), "sh", 10);
        // Root exec arrives with BPF tgid=49135 but observer ns_tgid=35862.
        assert!(matches!(
            scope.resolve_observed(49135, Some(35862), Some(49134), None, Some(5), "sh", 11),
            Attribution::Included(_)
        ));
        // Alias learned: child forked by BPF parent 49135 (now aliased) is
        // attributable even without ns_tgid for the child.
        assert!(matches!(
            scope.resolve_observed(49136, None, Some(49135), None, Some(6), "sleep", 12),
            Attribution::Included(_)
        ));
        // Child exec with its own observer-ns tgid learns its alias.
        assert!(matches!(
            scope.resolve_observed(49136, Some(35863), Some(49135), None, Some(6), "sleep", 13),
            Attribution::Included(_)
        ));
        scope.mark_exited(49136);
        scope.mark_exited(49135);
        assert!(scope.root_exited());
    }

    #[test]
    fn ns_tgid_does_not_admit_untracked_process() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root_with_aliases(35862, &[35862], Some(35861), Some(5), "sh", 10);
        // Unrelated process: BPF tgid=99999, ns_tgid=99999 not tracked.
        assert_eq!(
            scope.resolve_observed(99999, Some(99999), Some(1), None, Some(7), "other", 11),
            Attribution::OutOfScope
        );
        // BPF tgid differs but ns_tgid is also untracked: must not be admitted.
        assert_eq!(
            scope.resolve_observed(49135, Some(88888), Some(1), None, Some(8), "other", 12),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn ns_tgid_alias_learning_does_not_weaken_pid_reuse_detection() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root_with_aliases(35862, &[35862], Some(35861), Some(100), "root", 10);
        // Learn BPF alias.
        assert!(matches!(
            scope.resolve_observed(49135, Some(35862), Some(35861), None, Some(100), "root", 11),
            Attribution::Included(_)
        ));
        // Simulate confirmed PID reuse on the canonical identity: a new start_time
        // with /proc confirming different instance (lookup returns different start).
        // Rebuild tracker with a lookup that reports reuse for the canonical pid.
        let mut scope = tracker(RecordingScope::TargetTree, vec![info(35862, 35861, 999)]);
        scope.register_root_with_aliases(
            35862,
            &[35862, 49135],
            Some(35861),
            Some(100),
            "root",
            10,
        );
        // Different start_time arrives via BPF alias; lookup confirms 999 != 100.
        let result =
            scope.resolve_observed(49135, Some(35862), Some(35861), None, Some(999), "root", 12);
        // Root was marked exited due to confirmed reuse; new instance not admitted
        // without tracked ancestor.
        assert_eq!(result, Attribution::OutOfScope);
    }

    #[test]
    fn multiple_namespace_aliases_are_resolved_without_admitting_unknown_pids() {
        // Synthetic multi-level namespace view: same process seen as local 35862,
        // intermediate 5000, inner/global 49135. Only these aliases resolve.
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root_with_aliases(
            35862,
            &[35862, 5000, 49135],
            Some(35861),
            Some(5),
            "sh",
            10,
        );
        assert!(matches!(
            scope.resolve(35862, Some(35861), Some(5), "sh", 11),
            Attribution::Included(_)
        ));
        assert!(matches!(
            scope.resolve(5000, Some(35861), Some(5), "sh", 12),
            Attribution::Included(_)
        ));
        assert!(matches!(
            scope.resolve(49135, Some(35861), Some(5), "sh", 13),
            Attribution::Included(_)
        ));
        assert_eq!(
            scope.resolve(77777, Some(35861), Some(5), "sh", 14),
            Attribution::OutOfScope
        );
    }

    #[test]
    fn provisional_fork_upgrades_to_canonical_on_ns_tgid_exec() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "sh", 10);
        // Fork observed as raw BPF child 64570, parent is tracked root.
        let attr = scope.register_provisional(64570, Some(100), Some(6), "sleep", 11);
        assert!(matches!(attr, Attribution::Included(_)));
        assert!(scope.is_provisional(64570));
        // Exec arrives in child context with observer-ns tgid 51221.
        let attr =
            scope.resolve_observed(64570, Some(51221), Some(100), None, Some(6), "sleep", 12);
        let Attribution::Included(tracked) = attr else {
            panic!("expected included")
        };
        assert_eq!(tracked.tgid, 51221, "canonical must be observer-visible");
        assert!(!tracked.provisional);
        assert_eq!(tracked.process_instance_id, "boot:51221:6");
        // Raw alias still resolves.
        assert!(scope.get(64570).is_some());
        assert!(scope.get(51221).is_some());
    }

    #[test]
    fn duplicate_process_prevented_across_raw_and_canonical_ids() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "sh", 10);
        scope.register_provisional(64570, Some(100), Some(6), "sleep", 11);
        scope.resolve_observed(64570, Some(51221), Some(100), None, Some(6), "sleep", 12);
        // Same process seen again via raw or canonical must not create duplicate tracking.
        let before = scope.tracked_count();
        scope.resolve_observed(64570, Some(51221), Some(100), None, Some(6), "sleep", 13);
        scope.resolve_observed(51221, None, Some(100), None, Some(6), "sleep", 14);
        assert_eq!(scope.tracked_count(), before);
        let t = scope.get(51221).unwrap();
        assert_eq!(t.process_instance_id, "boot:51221:6");
    }

    #[test]
    fn same_raw_pid_different_start_time_is_pid_reuse_not_duplicate() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root(100, Some(1), Some(5), "sh", 10);
        scope.register_provisional(64570, Some(100), Some(6), "a", 11);
        scope.resolve_observed(64570, Some(51221), Some(100), None, Some(6), "a", 12);
        scope.mark_exited(51221);
        // Raw BPF PID reused by unrelated process (different start time, parent not tracked).
        let attr = scope.resolve_observed(64570, Some(99999), Some(1), None, Some(777), "b", 13);
        assert_eq!(attr, Attribution::OutOfScope);
    }

    #[test]
    fn parent_child_relationships_preserved_across_alias_mapping() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        // Root seen as raw 61527, canonical/observer 48180.
        scope.register_root_with_aliases(48180, &[48180], Some(1), Some(5), "sh", 10);
        scope.resolve_observed(61527, Some(48180), Some(1), None, Some(5), "sh", 11);
        // Child fork raw 64570 from raw parent 61527, later exec gives ns_tgid 51221.
        scope.register_provisional(64570, Some(61527), Some(6), "sleep", 12);
        let Attribution::Included(child) =
            scope.resolve_observed(64570, Some(51221), Some(61527), None, Some(6), "sleep", 13)
        else {
            panic!()
        };
        assert_eq!(child.tgid, 51221);
        assert_eq!(
            child.ppid,
            Some(48180),
            "parent must be canonical observer-visible"
        );
        assert_eq!(child.process_instance_id, "boot:51221:6");
    }

    #[test]
    fn multiple_descendants_keep_distinct_canonical_identities() {
        let mut scope = tracker(RecordingScope::TargetTree, vec![]);
        scope.register_root_with_aliases(48180, &[48180], Some(1), Some(5), "sh", 10);
        scope.resolve_observed(61527, Some(48180), Some(1), None, Some(5), "sh", 11);
        scope.register_provisional(64570, Some(61527), Some(6), "sleep", 12);
        scope.register_provisional(64571, Some(61527), Some(7), "true", 13);
        let Attribution::Included(a) =
            scope.resolve_observed(64570, Some(51221), Some(61527), None, Some(6), "sleep", 14)
        else {
            panic!()
        };
        let Attribution::Included(b) =
            scope.resolve_observed(64571, Some(51222), Some(61527), None, Some(7), "true", 15)
        else {
            panic!()
        };
        assert_eq!(a.tgid, 51221);
        assert_eq!(b.tgid, 51222);
        assert_ne!(a.process_instance_id, b.process_instance_id);
        assert_eq!(a.ppid, Some(48180));
        assert_eq!(b.ppid, Some(48180));
    }
}
