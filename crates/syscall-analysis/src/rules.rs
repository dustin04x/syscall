//! Deterministic behavioral rules A-F.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;

use syscall_core::{
    AnalysisConfidence, AnalysisFinding, AnalysisRuleMetadata, AnalysisSeverity, AnalysisTimeRange,
    Event, EventPayload, EventType,
};

use crate::config::{
    AnalysisConfig, RULE_FS_NET_CORRELATION, RULE_REPEATED_CONNECT, RULE_SENSITIVE_OPEN,
    RULE_SHELL_CHAIN, RULE_SHORT_LIVED_NET, RULE_TEMP_EXEC,
};
use crate::evidence::{event_summary, Evidence};

pub(crate) struct RuleOutcome {
    pub findings: Vec<AnalysisFinding>,
    pub limitations: Vec<String>,
}

impl RuleOutcome {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            limitations: Vec::new(),
        }
    }
}

pub(crate) fn metadata() -> Vec<AnalysisRuleMetadata> {
    vec![
        AnalysisRuleMetadata {
            rule_id: RULE_SHELL_CHAIN.to_owned(),
            version: 1,
            title: "Shell execution chain".to_owned(),
            description: "A shell-rooted process tree contains a child that spawns at least one further descendant.".to_owned(),
            conditions: vec![
                "A process instance executing a known shell (sh, bash, dash, zsh, ksh, fish) is the root.".to_owned(),
                "At least two descendants are linked through recorded process-instance ancestry.".to_owned(),
                "Maximum observed depth is at least two below the shell root.".to_owned(),
            ],
            required_evidence: vec![
                "Recorded process_exec and process_fork events with canonical process-instance identity.".to_owned(),
                "Parent-process-instance links derived unambiguously from persisted evidence.".to_owned(),
            ],
            exclusions: vec![
                "Shells with only one child, or children that do not spawn further processes.".to_owned(),
                "Trees whose ancestry cannot be reconstructed are not promoted as high confidence.".to_owned(),
            ],
            known_false_positives: vec![
                "Build scripts, package managers, service wrappers, and interactive shells routinely create chains.".to_owned(),
                "A chain alone is not malicious; inspect executable paths, file access, and network activity.".to_owned(),
            ],
            severity_rationale: "Low: a shell chain is common operational behavior and is presented as context, not a verdict.".to_owned(),
            confidence_rationale: "High only when every chain link has resolved ancestry and the session verifies as complete.".to_owned(),
            default_severity: AnalysisSeverity::Low,
            default_confidence: AnalysisConfidence::Medium,
        },
        AnalysisRuleMetadata {
            rule_id: RULE_TEMP_EXEC.to_owned(),
            version: 1,
            title: "Execution from a temporary location".to_owned(),
            description: "An observed executable path is located under a configured temporary or writable directory.".to_owned(),
            conditions: vec![
                "A process_exec payload contains a non-empty executable path.".to_owned(),
                "The lexically normalized absolute path equals a configured temporary directory or is beneath it at a path-component boundary.".to_owned(),
            ],
            required_evidence: vec!["Recorded process_exec filename for the process instance.".to_owned()],
            exclusions: vec![
                "Substring-only matches such as /tmpfoo are never treated as /tmp.".to_owned(),
                "Relative or empty executable paths are not guessed or resolved.".to_owned(),
            ],
            known_false_positives: vec![
                "Installers, package builds, test harnesses, and legitimate self-updating tools commonly execute from temporary directories.".to_owned(),
            ],
            severity_rationale: "Medium: temporary execution is a useful contextual indicator but not proof of malicious intent.".to_owned(),
            confidence_rationale: "High for an absolute observed path; reduced when the session is incomplete.".to_owned(),
            default_severity: AnalysisSeverity::Medium,
            default_confidence: AnalysisConfidence::High,
        },
        AnalysisRuleMetadata {
            rule_id: RULE_SENSITIVE_OPEN.to_owned(),
            version: 1,
            title: "Sensitive system-path access attempt".to_owned(),
            description: "A process attempted to open a path on the conservative sensitive-path list.".to_owned(),
            conditions: vec![
                "A file_open event matches a configured sensitive path exactly or beneath it at a component boundary.".to_owned(),
                "Successful and failed attempts are reported separately.".to_owned(),
                "Unresolved relative paths are reported as informational only when their basename matches a sensitive entry.".to_owned(),
            ],
            required_evidence: vec![
                "Recorded file_open event with raw path, result, success, and errno.".to_owned(),
                "Canonical process identity from the persisted event.".to_owned(),
            ],
            exclusions: vec![
                "An open event does not prove that file contents were read or written.".to_owned(),
                "Relative paths and dirfd resolution are unavailable and are not guessed.".to_owned(),
            ],
            known_false_positives: vec![
                "Authentication, backup, configuration-management, and monitoring software legitimately accesses credential files.".to_owned(),
            ],
            severity_rationale: "High for successful opens of credential stores, medium for other successful sensitive opens, low for failed attempts, informational for unresolved relative paths.".to_owned(),
            confidence_rationale: "High for a direct absolute path/result; medium for a failed attempt; low when a relative path cannot be resolved.".to_owned(),
            default_severity: AnalysisSeverity::Medium,
            default_confidence: AnalysisConfidence::High,
        },
        AnalysisRuleMetadata {
            rule_id: RULE_REPEATED_CONNECT.to_owned(),
            version: 1,
            title: "Repeated failed network connections".to_owned(),
            description: "One process instance made repeated failed connection attempts to the same destination, port, and result within the configured window.".to_owned(),
            conditions: vec![
                "At least the configured number of failed network_connect events share process instance, family, destination, port, and raw result.".to_owned(),
                "All attempts fit inside correlation_window_ns.".to_owned(),
            ],
            required_evidence: vec!["Recorded network_connect events with result, error, destination, and process-instance identity.".to_owned()],
            exclusions: vec![
                "A single refused connection is not reported by this rule.".to_owned(),
                "Successful connects are not counted as failures.".to_owned(),
            ],
            known_false_positives: vec![
                "Retry loops, unavailable local services, and network scanners can produce repeated refusals.".to_owned(),
            ],
            severity_rationale: "Medium: repetition distinguishes a pattern from one failed attempt, without asserting intent.".to_owned(),
            confidence_rationale: "High when the session is complete; reduced when losses or unresolved identity are present.".to_owned(),
            default_severity: AnalysisSeverity::Medium,
            default_confidence: AnalysisConfidence::High,
        },
        AnalysisRuleMetadata {
            rule_id: RULE_FS_NET_CORRELATION.to_owned(),
            version: 1,
            title: "Filesystem activity followed by network attempt".to_owned(),
            description: "A filesystem open preceded a network connection attempt by the same process instance or a process-tree relative within the configured window.".to_owned(),
            conditions: vec![
                "A file_open event is followed by a network_connect event in persisted chronological order.".to_owned(),
                "The elapsed time is within correlation_window_ns.".to_owned(),
                "Same-process and process-tree correlations are labeled separately.".to_owned(),
            ],
            required_evidence: vec!["Recorded file_open and network_connect events with event ordering and process-instance identity.".to_owned()],
            exclusions: vec![
                "The rule never claims that a file was transmitted or that exfiltration occurred.".to_owned(),
                "Temporal proximity alone does not establish causation.".to_owned(),
            ],
            known_false_positives: vec![
                "Applications routinely open configuration or library files before making network requests.".to_owned(),
            ],
            severity_rationale: "Low: this is a correlation for investigation, not a claim of data transfer.".to_owned(),
            confidence_rationale: "Medium: both events are direct, but their causal relationship is not proven; reduced for incomplete sessions.".to_owned(),
            default_severity: AnalysisSeverity::Low,
            default_confidence: AnalysisConfidence::Medium,
        },
        AnalysisRuleMetadata {
            rule_id: RULE_SHORT_LIVED_NET.to_owned(),
            version: 1,
            title: "Short-lived network process".to_owned(),
            description: "A process executed, made a network connection attempt, and exited within the configured short-lived window.".to_owned(),
            conditions: vec![
                "Recorded exec, network_connect, and exit events exist for the same process instance.".to_owned(),
                "The connection occurred after exec and before exit.".to_owned(),
                "The exec-to-exit duration is at or below short_lived_window_ns.".to_owned(),
            ],
            required_evidence: vec!["Recorded process_exec, network_connect, and process_exit events with timestamps.".to_owned()],
            exclusions: vec![
                "Processes without a recorded exit are not classified by this rule.".to_owned(),
                "Short lifetime by itself is not presented as suspicious.".to_owned(),
            ],
            known_false_positives: vec![
                "CLI tools, health checks, package operations, and one-shot network utilities are naturally short-lived.".to_owned(),
            ],
            severity_rationale: "Low: the rule supplies timing context, not a verdict.".to_owned(),
            confidence_rationale: "Medium when exec, connect, and exit are all recorded; low when evidence is incomplete.".to_owned(),
            default_severity: AnalysisSeverity::Low,
            default_confidence: AnalysisConfidence::Medium,
        },
    ]
}

pub(crate) fn evaluate(
    rule_id: &str,
    evidence: &Evidence,
    config: &AnalysisConfig,
) -> Result<RuleOutcome, crate::AnalysisError> {
    match rule_id {
        RULE_SHELL_CHAIN => Ok(rule_shell_chain(evidence)),
        RULE_TEMP_EXEC => Ok(rule_temp_exec(evidence, config)),
        RULE_SENSITIVE_OPEN => Ok(rule_sensitive_open(evidence, config)),
        RULE_REPEATED_CONNECT => Ok(rule_repeated_connect(evidence, config)),
        RULE_FS_NET_CORRELATION => Ok(rule_fs_net_correlation(evidence, config)),
        RULE_SHORT_LIVED_NET => Ok(rule_short_lived_net(evidence, config)),
        _ => Err(crate::AnalysisError::UnknownRule(
            rule_id.to_owned(),
            crate::ALL_RULE_IDS.join(", "),
        )),
    }
}

fn rule_shell_chain(evidence: &Evidence) -> RuleOutcome {
    let mut out = RuleOutcome::new();
    let children = evidence.children_map();
    let mut roots: Vec<String> = evidence
        .processes
        .iter()
        .filter(|process| is_shell(process.executable.as_deref(), &process.comm))
        .map(|process| process.process_instance_id.clone())
        .collect();
    roots.sort();

    for root_id in roots {
        let Some(root) = evidence.process(&root_id) else {
            continue;
        };
        let mut visited = HashSet::new();
        visited.insert(root_id.clone());
        let mut queue = VecDeque::from([(root_id.clone(), 0u32)]);
        let mut descendants = Vec::new();
        let mut max_depth = 0u32;
        while let Some((id, depth)) = queue.pop_front() {
            if let Some(kids) = children.get(&id) {
                for child in kids {
                    if visited.insert(child.clone()) {
                        max_depth = max_depth.max(depth + 1);
                        descendants.push(child.clone());
                        if descendants.len() >= 1_000 {
                            break;
                        }
                        queue.push_back((child.clone(), depth + 1));
                    }
                }
            }
            if descendants.len() >= 1_000 {
                out.limitations.push(
                    "Shell-chain traversal reached its 1,000-descendant safety bound.".to_owned(),
                );
                break;
            }
        }
        if descendants.len() < 2 || max_depth < 2 {
            continue;
        }

        let chain = first_chain(&root_id, &children, 10);
        let mut process_ids = vec![root_id.clone()];
        process_ids.extend(descendants.iter().cloned());
        process_ids.sort();
        process_ids.dedup();
        let tree_ids: HashSet<&str> = process_ids.iter().map(String::as_str).collect();
        let events: Vec<&Event> = evidence
            .events
            .iter()
            .filter(|event| {
                tree_ids.contains(event.process_instance_id.as_str())
                    && matches!(
                        event.event_type,
                        EventType::ProcessExec | EventType::ProcessFork
                    )
            })
            .take(100)
            .collect();

        let mut limitations = base_limitations(evidence);
        if evidence.processes.iter().any(|process| {
            tree_ids.contains(process.process_instance_id.as_str()) && process.ancestry_unresolved
        }) {
            limitations.push("At least one tree relationship is unresolved; the displayed chain is incomplete or provisional.".to_owned());
        }
        let (mut confidence, mut confidence_limits) =
            adjust_confidence(evidence, AnalysisConfidence::High);
        limitations.append(&mut confidence_limits);
        if descendants.iter().any(|id| {
            evidence
                .process(id)
                .is_some_and(|process| process.ancestry_unresolved)
        }) {
            confidence = lower_confidence(confidence);
            limitations.push(
                "Confidence was reduced because at least one descendant's process ancestry is unresolved."
                    .to_owned(),
            );
        }
        if chain.len() < 2 {
            limitations
                .push("No complete root-to-descendant chain could be reconstructed.".to_owned());
        }
        let chain_text = chain
            .iter()
            .filter_map(|id| evidence.process(id))
            .map(|p| format!("{}({})", p.comm, p.pid))
            .collect::<Vec<_>>()
            .join(" -> ");
        let title = format!(
            "Shell execution chain rooted at {} ({})",
            root.comm, root.pid
        );
        let explanation = format!(
            "{} started at {} and has {} descendant process instance(s) across a maximum observed depth of {}. Recorded chain: {}.",
            root.executable.as_deref().unwrap_or(&root.comm),
            syscall_core::timefmt::format_unix_ns_utc(root.first_seen_ns),
            descendants.len(),
            max_depth,
            if chain_text.is_empty() { "(no full chain)".to_owned() } else { chain_text }
        );
        let significance = "Shell-rooted chains are normal in builds, scripts, and service wrappers. They deserve attention when the shell path, child executables, sensitive file access, or network activity is unexpected in context.".to_owned();
        if let Some(finding) = build_finding(
            evidence,
            &metadata_for(RULE_SHELL_CHAIN),
            &root_id,
            AnalysisSeverity::Low,
            confidence,
            title,
            explanation,
            significance,
            &events,
            &process_ids,
            limitations,
            vec![
                "Review the child executable paths and their arguments, then inspect adjacent file and network findings.".to_owned(),
                "Determine whether this shell chain is expected for the recorded target and host role.".to_owned(),
            ],
            "process_tree",
        ) {
            out.findings.push(finding);
        }
    }
    out
}

fn rule_temp_exec(evidence: &Evidence, config: &AnalysisConfig) -> RuleOutcome {
    let mut out = RuleOutcome::new();
    let mut by_instance: BTreeMap<String, Vec<&Event>> = BTreeMap::new();
    let mut missing_paths = 0u64;
    for event in &evidence.events {
        let EventPayload::ProcessExec { filename, .. } = &event.payload else {
            continue;
        };
        if filename.is_empty() {
            missing_paths += 1;
            continue;
        }
        if config.temporary_path(filename).is_some() {
            by_instance
                .entry(event.process_instance_id.clone())
                .or_default()
                .push(event);
        }
    }
    if missing_paths > 0 {
        out.limitations.push(format!(
            "{missing_paths} process_exec event(s) had no observed executable path; temporary-location evaluation did not guess one."
        ));
    }
    for (instance_id, events) in by_instance {
        let Some(first) = events.first() else {
            continue;
        };
        let EventPayload::ProcessExec { filename, .. } = &first.payload else {
            continue;
        };
        let Some(directory) = config.temporary_path(filename) else {
            continue;
        };
        let Some(process) = evidence.process(&instance_id) else {
            continue;
        };
        let (confidence, mut limits) = adjust_confidence(evidence, AnalysisConfidence::High);
        if process.identity_unresolved {
            limits.push("The process instance identity is provisional; the executable-to-instance link is limited.".to_owned());
        }
        let mut limitations = base_limitations(evidence);
        limitations.append(&mut limits);
        let explanation = format!(
            "Process instance {} ({}, pid {}) executed {} at {}. The normalized path is inside the configured temporary directory {}.",
            instance_id,
            process.comm,
            process.pid,
            filename,
            syscall_core::timefmt::format_unix_ns_utc(first.timestamp_ns),
            directory
        );
        let significance = "Temporary and writable directories are common staging locations for downloaded or generated executables. Legitimate installers, builds, and tests also use them, so this is contextual evidence rather than a verdict.".to_owned();
        if let Some(finding) = build_finding(
            evidence,
            &metadata_for(RULE_TEMP_EXEC),
            &instance_id,
            AnalysisSeverity::Medium,
            confidence,
            format!("Executable launched from {}", directory),
            explanation,
            significance,
            &events,
            std::slice::from_ref(&instance_id),
            limitations,
            vec![
                "Check how the executable arrived in the temporary directory and whether the parent process explains it.".to_owned(),
                "Inspect adjacent file-open and network findings for this process instance.".to_owned(),
            ],
            "same_process",
        ) {
            out.findings.push(finding);
        }
    }
    out
}

fn rule_sensitive_open(evidence: &Evidence, config: &AnalysisConfig) -> RuleOutcome {
    let mut out = RuleOutcome::new();
    let leaves = config.sensitive_leaf_names();
    let mut groups: BTreeMap<(String, String, String), Vec<&Event>> = BTreeMap::new();
    let mut truncated_paths = 0u64;
    for event in &evidence.events {
        let EventPayload::FileOpen {
            path,
            path_is_absolute,
            path_truncated,
            success,
            ..
        } = &event.payload
        else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        if *path_truncated {
            truncated_paths += 1;
            continue;
        }
        if *path_is_absolute {
            if let Some(entry) = config.sensitive_path(path) {
                let outcome = if *success { "success" } else { "failure" };
                groups
                    .entry((event.process_instance_id.clone(), entry, outcome.to_owned()))
                    .or_default()
                    .push(event);
            }
        } else if let Some(name) = Path::new(path).file_name().and_then(|n| n.to_str()) {
            if leaves.iter().any(|leaf| leaf == name) {
                groups
                    .entry((
                        event.process_instance_id.clone(),
                        format!("<unresolved-relative>/{name}"),
                        "relative_unresolved".to_owned(),
                    ))
                    .or_default()
                    .push(event);
            }
        }
    }

    if truncated_paths > 0 {
        out.limitations.push(format!(
            "{truncated_paths} file_open event(s) had truncated paths; sensitive-path matching was not attempted for them."
        ));
    }

    for ((instance_id, path, outcome), events) in groups {
        let Some(process) = evidence.process(&instance_id) else {
            continue;
        };
        let (severity, confidence, title, significance) = match outcome.as_str() {
            "success" => {
                let high = path.contains("shadow")
                    || path.contains("sudoers")
                    || path.contains("gshadow")
                    || path.contains("ssh_host_");
                (
                    if high {
                        AnalysisSeverity::High
                    } else {
                        AnalysisSeverity::Medium
                    },
                    AnalysisConfidence::High,
                    format!("Sensitive path opened: {path}"),
                    "A successful open returned a file descriptor for a sensitive path. This does not prove that contents were read, written, or exfiltrated.",
                )
            }
            "failure" => (
                AnalysisSeverity::Low,
                AnalysisConfidence::Medium,
                format!("Sensitive path open failed: {path}"),
                "A failed attempt can indicate probing or a permissions/configuration mismatch; the file was not opened.",
            ),
            _ => (
                AnalysisSeverity::Informational,
                AnalysisConfidence::Low,
                format!("Unresolved relative path resembles sensitive entry: {path}"),
                "The recorded relative path cannot be resolved without the process working directory and dirfd; this is informational only.",
            ),
        };
        let (confidence, mut confidence_limits) = adjust_confidence(evidence, confidence);
        let mut limitations = base_limitations(evidence);
        limitations.append(&mut confidence_limits);
        if outcome == "relative_unresolved" {
            limitations.push(
                "Relative-path resolution is unavailable; the target file is not confirmed."
                    .to_owned(),
            );
        }
        let explanation = format!(
            "Process instance {} ({}, pid {}) recorded {} {} attempt(s) on {}. The raw result is preserved in the supporting events.",
            instance_id,
            process.comm,
            process.pid,
            events.len(),
            outcome.replace('_', " "),
            path
        );
        if let Some(finding) = build_finding(
            evidence,
            &metadata_for(RULE_SENSITIVE_OPEN),
            &format!("{instance_id}:{path}:{outcome}"),
            severity,
            confidence,
            title,
            explanation,
            significance.to_owned(),
            &events,
            std::slice::from_ref(&instance_id),
            limitations,
            vec![
                "Determine whether this process is expected to access the path and whether the attempt succeeded.".to_owned(),
                "Correlate with subsequent file reads/writes only if such telemetry exists; an open is not a read.".to_owned(),
            ],
            "same_process",
        ) {
            out.findings.push(finding);
        }
    }
    out
}

fn rule_repeated_connect(evidence: &Evidence, config: &AnalysisConfig) -> RuleOutcome {
    let mut out = RuleOutcome::new();
    let mut groups: BTreeMap<(String, String, u16, i64), Vec<&Event>> = BTreeMap::new();
    for event in &evidence.events {
        let EventPayload::NetworkConnect {
            family,
            destination_address,
            destination_port,
            result,
            success,
            ..
        } = &event.payload
        else {
            continue;
        };
        if *success {
            continue;
        }
        groups
            .entry((
                event.process_instance_id.clone(),
                format!("{}:{}", family.as_str(), destination_address),
                *destination_port,
                *result,
            ))
            .or_default()
            .push(event);
    }

    for ((instance_id, destination, port, result), events) in groups {
        let mut events = events;
        events.sort_by_key(|event| (event.timestamp_ns, event.monotonic_ns, event.id));
        let threshold = usize::try_from(config.repeated_connection_threshold).unwrap_or(usize::MAX);
        let mut start = 0usize;
        let mut emitted = false;
        for end in 0..events.len() {
            while events[end]
                .timestamp_ns
                .saturating_sub(events[start].timestamp_ns)
                > config.correlation_window_ns
            {
                start += 1;
            }
            if end - start + 1 >= threshold {
                let window = &events[start..=end];
                if let Some(first) = window.first() {
                    let Some(process) = evidence.process(&instance_id) else {
                        continue;
                    };
                    let (confidence, mut limits) =
                        adjust_confidence(evidence, AnalysisConfidence::High);
                    if process.identity_unresolved {
                        limits.push(
                            "Process identity is provisional; attempts may not all belong to one confirmed process instance."
                                .to_owned(),
                        );
                    }
                    let mut limitations = base_limitations(evidence);
                    limitations.append(&mut limits);
                    limitations.push(
                        "A failed connect proves only that the attempt did not establish a connection; it does not prove scanning or intent."
                            .to_owned(),
                    );
                    let explanation = format!(
                        "Process instance {} ({}, pid {}) made {} failed connection attempt(s) to {} port {} with raw result {} between {} and {}. The attempts fit within the configured {} ns window.",
                        instance_id,
                        process.comm,
                        process.pid,
                        window.len(),
                        destination,
                        port,
                        result,
                        syscall_core::timefmt::format_unix_ns_utc(first.timestamp_ns),
                        syscall_core::timefmt::format_unix_ns_utc(window.last().map(|e| e.timestamp_ns).unwrap_or(first.timestamp_ns)),
                        config.correlation_window_ns
                    );
                    let significance = "Repeated failures to one destination can reflect retry logic, a missing service, or deliberate probing. The rule reports the pattern without asserting intent.".to_owned();
                    if let Some(finding) = build_finding(
                        evidence,
                        &metadata_for(RULE_REPEATED_CONNECT),
                        &format!("{instance_id}:{destination}:{port}:{result}"),
                        AnalysisSeverity::Medium,
                        confidence,
                        format!("Repeated failed connections to {destination}:{port}"),
                        explanation,
                        significance,
                        window,
                        std::slice::from_ref(&instance_id),
                        limitations,
                        vec![
                            "Identify the process and whether retry behavior is expected."
                                .to_owned(),
                            "Check whether the destination and port are sanctioned for this host."
                                .to_owned(),
                        ],
                        "same_process",
                    ) {
                        out.findings.push(finding);
                    }
                    emitted = true;
                }
                start = end + 1;
            }
        }
        if emitted {
            continue;
        }
    }
    out
}

fn rule_fs_net_correlation(evidence: &Evidence, config: &AnalysisConfig) -> RuleOutcome {
    let mut out = RuleOutcome::new();
    let mut files_by_instance: BTreeMap<String, Vec<&Event>> = BTreeMap::new();
    let mut nets_by_instance: BTreeMap<String, Vec<&Event>> = BTreeMap::new();
    for event in &evidence.events {
        match event.event_type {
            EventType::FileOpen => files_by_instance
                .entry(event.process_instance_id.clone())
                .or_default()
                .push(event),
            EventType::NetworkConnect => nets_by_instance
                .entry(event.process_instance_id.clone())
                .or_default()
                .push(event),
            _ => {}
        }
    }

    for (instance_id, nets) in &nets_by_instance {
        let Some(files) = files_by_instance.get(instance_id) else {
            continue;
        };
        let Some(first_net) = nets.iter().find(|net| {
            files.iter().any(|file| {
                file.timestamp_ns <= net.timestamp_ns
                    && net.timestamp_ns.saturating_sub(file.timestamp_ns)
                        <= config.correlation_window_ns
            })
        }) else {
            continue;
        };
        let Some(file) = files.iter().rev().find(|file| {
            file.timestamp_ns <= first_net.timestamp_ns
                && first_net.timestamp_ns.saturating_sub(file.timestamp_ns)
                    <= config.correlation_window_ns
        }) else {
            continue;
        };
        let window_nets: Vec<&Event> = nets
            .iter()
            .copied()
            .filter(|net| {
                net.timestamp_ns >= file.timestamp_ns
                    && net.timestamp_ns.saturating_sub(file.timestamp_ns)
                        <= config.correlation_window_ns
            })
            .collect();
        if window_nets.is_empty() {
            continue;
        }
        let Some(process) = evidence.process(instance_id) else {
            continue;
        };
        let (confidence, mut limits) = adjust_confidence(evidence, AnalysisConfidence::Medium);
        let mut limitations = base_limitations(evidence);
        limitations.append(&mut limits);
        limitations.push(
            "Temporal ordering does not prove that the opened file was transmitted or that the connection carried its contents."
                .to_owned(),
        );
        let mut events = vec![*file];
        events.extend(window_nets.iter().copied());
        let explanation = format!(
            "Process instance {} ({}, pid {}) opened {:?} at {} and then made {} connection attempt(s) within the configured window; the first attempt was {}.",
            instance_id,
            process.comm,
            process.pid,
            file_path(file),
            syscall_core::timefmt::format_unix_ns_utc(file.timestamp_ns),
            window_nets.len(),
            syscall_core::timefmt::format_unix_ns_utc(first_net.timestamp_ns)
        );
        if let Some(finding) = build_finding(
            evidence,
            &metadata_for(RULE_FS_NET_CORRELATION),
            &format!("{instance_id}:same-process"),
            AnalysisSeverity::Low,
            confidence,
            format!("Filesystem activity before network attempt: {}", process.comm),
            explanation,
            "This ordering is a correlation lead. It does not establish that a file was read, transmitted, or exfiltrated.".to_owned(),
            &events,
            std::slice::from_ref(instance_id),
            limitations,
            vec![
                "Inspect the opened path and destination in context; determine whether the process normally does both.".to_owned(),
                "Check for additional evidence of data handling; SYSCALL does not record file contents or payloads.".to_owned(),
            ],
            "same_process",
        ) {
            out.findings.push(finding);
        }
    }

    // Process-tree correlation, kept separate from same-process findings.
    let parent_map = evidence.parent_map();
    let children = evidence.children_map();
    let mut seen_pairs = HashSet::new();
    for (net_instance, nets) in &nets_by_instance {
        let related = related_instances(net_instance, &parent_map, &children);
        for other in related {
            if other == *net_instance {
                continue;
            }
            let Some(files) = files_by_instance.get(&other) else {
                continue;
            };
            for net in nets {
                let Some(file) = files.iter().rev().find(|file| {
                    file.timestamp_ns <= net.timestamp_ns
                        && net.timestamp_ns.saturating_sub(file.timestamp_ns)
                            <= config.correlation_window_ns
                }) else {
                    continue;
                };
                let pair = (other.clone(), net_instance.clone());
                if !seen_pairs.insert(pair.clone()) {
                    continue;
                }
                if seen_pairs.len() > 200 {
                    out.limitations.push(
                        "Process-tree filesystem/network correlation reached its 200-pair safety bound."
                            .to_owned(),
                    );
                    break;
                }
                let relationship = if is_ancestor(&other, net_instance, &parent_map) {
                    "ancestor"
                } else {
                    "descendant"
                };
                let Some(file_process) = evidence.process(&other) else {
                    continue;
                };
                let Some(net_process) = evidence.process(net_instance) else {
                    continue;
                };
                let (confidence, mut limits) = adjust_confidence(evidence, AnalysisConfidence::Low);
                let mut limitations = base_limitations(evidence);
                limitations.append(&mut limits);
                limitations.push(
                    "The two events are in related process instances, not the same process; temporal and tree proximity do not prove causation."
                        .to_owned(),
                );
                let events = [*file, *net];
                let explanation = format!(
                    "Process {} ({}, pid {}) opened {:?} at {}, then related {} process {} ({}, pid {}) attempted a network connection at {}.",
                    file_process.comm,
                    file_process.pid,
                    other,
                    file_path(file),
                    syscall_core::timefmt::format_unix_ns_utc(file.timestamp_ns),
                    relationship,
                    net_process.comm,
                    net_process.pid,
                    net_instance,
                    syscall_core::timefmt::format_unix_ns_utc(net.timestamp_ns)
                );
                if let Some(finding) = build_finding(
                    evidence,
                    &metadata_for(RULE_FS_NET_CORRELATION),
                    &format!("{other}->{net_instance}:tree"),
                    AnalysisSeverity::Low,
                    confidence,
                    "Filesystem/network correlation across a process tree".to_owned(),
                    explanation,
                    "A related process performed filesystem activity before another process attempted a connection. This is an investigative lead, not evidence of transfer.".to_owned(),
                    &events,
                    &[other.clone(), net_instance.clone()],
                    limitations,
                    vec![
                        "Reconstruct the parent/child relationship and determine whether the file and destination are expected together.".to_owned(),
                        "Do not infer exfiltration; SYSCALL records neither file contents nor network payloads.".to_owned(),
                    ],
                    "process_tree",
                ) {
                    out.findings.push(finding);
                }
                break;
            }
        }
    }
    out
}

fn rule_short_lived_net(evidence: &Evidence, config: &AnalysisConfig) -> RuleOutcome {
    let mut out = RuleOutcome::new();
    let mut missing_exit = 0u64;
    let mut by_instance: BTreeMap<String, Vec<&Event>> = BTreeMap::new();
    for event in &evidence.events {
        by_instance
            .entry(event.process_instance_id.clone())
            .or_default()
            .push(event);
    }
    for (instance, events) in &by_instance {
        let Some(process) = evidence.process(instance) else {
            continue;
        };
        let Some(exec) = events
            .iter()
            .find(|event| event.event_type == EventType::ProcessExec)
        else {
            continue;
        };
        let nets: Vec<&Event> = events
            .iter()
            .copied()
            .filter(|event| {
                event.event_type == EventType::NetworkConnect
                    && event.timestamp_ns >= exec.timestamp_ns
            })
            .collect();
        if nets.is_empty() {
            continue;
        }
        let Some(exit) = events.iter().find(|event| {
            event.event_type == EventType::ProcessExit && event.timestamp_ns >= exec.timestamp_ns
        }) else {
            missing_exit += 1;
            continue;
        };
        let duration = exit.timestamp_ns.saturating_sub(exec.timestamp_ns);
        if duration > config.short_lived_window_ns {
            continue;
        }
        let Some(first_net) = nets.first() else {
            continue;
        };
        if first_net.timestamp_ns > exit.timestamp_ns {
            continue;
        }
        let mut included = vec![*exec];
        included.extend(
            nets.iter()
                .copied()
                .filter(|net| net.timestamp_ns <= exit.timestamp_ns),
        );
        included.push(*exit);
        let (confidence, mut limits) = adjust_confidence(evidence, AnalysisConfidence::Medium);
        let mut limitations = base_limitations(evidence);
        limitations.append(&mut limits);
        limitations.push(
            "Short lifetime is timing context only; it is not evidence of malicious behavior."
                .to_owned(),
        );
        let explanation = format!(
            "Process instance {} ({}, pid {}) executed at {}, attempted {} network connection(s), and exited at {}; observed lifetime was {} ns (configured threshold {} ns).",
            instance,
            process.comm,
            process.pid,
            syscall_core::timefmt::format_unix_ns_utc(exec.timestamp_ns),
            nets.iter().filter(|net| net.timestamp_ns <= exit.timestamp_ns).count(),
            syscall_core::timefmt::format_unix_ns_utc(exit.timestamp_ns),
            duration,
            config.short_lived_window_ns
        );
        if let Some(finding) = build_finding(
            evidence,
            &metadata_for(RULE_SHORT_LIVED_NET),
            instance,
            AnalysisSeverity::Low,
            confidence,
            format!("Short-lived network process: {}", process.comm),
            explanation,
            "Many legitimate utilities are short-lived and network-active. Evaluate the executable path, destination, and surrounding context rather than lifetime alone.".to_owned(),
            &included,
            std::slice::from_ref(instance),
            limitations,
            vec![
                "Identify the destination and whether a one-shot network operation is expected.".to_owned(),
                "Inspect the executable path and parent process for context.".to_owned(),
            ],
            "same_process",
        ) {
            out.findings.push(finding);
        }
    }
    if missing_exit > 0 {
        out.limitations.push(format!(
            "{missing_exit} network-active process instance(s) had no recorded exit; short-lived classification was not attempted for them."
        ));
    }
    out
}

fn metadata_for(rule_id: &str) -> AnalysisRuleMetadata {
    metadata()
        .into_iter()
        .find(|metadata| metadata.rule_id == rule_id)
        .expect("rule metadata is defined for every implemented rule")
}

#[allow(clippy::too_many_arguments)]
fn build_finding(
    evidence: &Evidence,
    rule: &AnalysisRuleMetadata,
    key: &str,
    severity: AnalysisSeverity,
    confidence: AnalysisConfidence,
    title: String,
    explanation: String,
    significance: String,
    events: &[&Event],
    process_ids: &[String],
    limitations: Vec<String>,
    next_steps: Vec<String>,
    correlation: &str,
) -> Option<AnalysisFinding> {
    let supporting_events = evidence.supporting_events(events);
    if supporting_events.is_empty() {
        return None;
    }
    let event_ids: Vec<i64> = supporting_events
        .iter()
        .map(|event| event.event_id)
        .collect();
    let start_ns = supporting_events
        .iter()
        .map(|event| event.timestamp_ns)
        .min()
        .unwrap_or(0);
    let end_ns = supporting_events
        .iter()
        .map(|event| event.timestamp_ns)
        .max()
        .unwrap_or(start_ns);
    let mut process_ids = process_ids.to_vec();
    process_ids.sort();
    process_ids.dedup();
    let related_processes: Vec<_> = process_ids
        .iter()
        .filter_map(|id| evidence.process_ref(id))
        .collect();
    let mut pids: Vec<i32> = related_processes
        .iter()
        .map(|process| process.pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    let mut limitations = limitations;
    limitations.sort();
    limitations.dedup();
    let finding_id = format!("{}:{:016x}", rule.rule_id, stable_hash(key));
    Some(AnalysisFinding {
        finding_id,
        rule_id: rule.rule_id.clone(),
        rule_version: rule.version,
        severity,
        confidence,
        title,
        explanation,
        significance,
        event_ids,
        process_instance_ids: process_ids,
        pids,
        time_range: AnalysisTimeRange { start_ns, end_ns },
        related_findings: Vec::new(),
        limitations,
        next_steps,
        supporting_events,
        related_processes,
        correlation: correlation.to_owned(),
    })
}

fn base_limitations(evidence: &Evidence) -> Vec<String> {
    let mut out = Vec::new();
    if !evidence.complete() {
        out.push(
            "Session evidence is incomplete, unverified, or truncated; this finding may not represent all activity."
                .to_owned(),
        );
    }
    out
}

fn adjust_confidence(
    evidence: &Evidence,
    base: AnalysisConfidence,
) -> (AnalysisConfidence, Vec<String>) {
    if evidence.complete() {
        return (base, Vec::new());
    }
    let adjusted = lower_confidence(base);
    let limitations = if adjusted == base {
        Vec::new()
    } else {
        vec![
            "Confidence was reduced because the session is incomplete, unverified, or truncated."
                .to_owned(),
        ]
    };
    (adjusted, limitations)
}

fn lower_confidence(confidence: AnalysisConfidence) -> AnalysisConfidence {
    match confidence {
        AnalysisConfidence::High => AnalysisConfidence::Medium,
        AnalysisConfidence::Medium => AnalysisConfidence::Low,
        AnalysisConfidence::Low => AnalysisConfidence::Low,
    }
}

fn is_shell(executable: Option<&str>, comm: &str) -> bool {
    const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "fish", "ash"];
    executable
        .and_then(|path| Path::new(path).file_name().and_then(|name| name.to_str()))
        .map(|name| SHELLS.contains(&name))
        .unwrap_or_else(|| SHELLS.contains(&comm))
}

fn first_chain(
    root: &str,
    children: &BTreeMap<String, Vec<String>>,
    max_nodes: usize,
) -> Vec<String> {
    let mut chain = vec![root.to_owned()];
    let mut current = root.to_owned();
    for _ in 0..max_nodes {
        let Some(kids) = children.get(&current) else {
            break;
        };
        let Some(next) = kids
            .iter()
            .find(|kid| children.get(*kid).is_some_and(|v| !v.is_empty()))
            .or_else(|| kids.first())
        else {
            break;
        };
        if chain.iter().any(|value| value == next) {
            break;
        }
        chain.push(next.clone());
        current = next.clone();
    }
    chain
}

fn related_instances(
    instance: &str,
    parents: &BTreeMap<String, String>,
    children: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = instance.to_owned();
    let mut guard = 0;
    while let Some(parent) = parents.get(&current) {
        if out.iter().any(|value| value == parent) {
            break;
        }
        out.push(parent.clone());
        current = parent.clone();
        guard += 1;
        if guard >= 64 {
            break;
        }
    }
    let mut queue = VecDeque::from([instance.to_owned()]);
    let mut seen = HashSet::new();
    seen.insert(instance.to_owned());
    while let Some(id) = queue.pop_front() {
        if let Some(kids) = children.get(&id) {
            for kid in kids {
                if seen.insert(kid.clone()) {
                    out.push(kid.clone());
                    queue.push_back(kid.clone());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn is_ancestor(candidate: &str, instance: &str, parents: &BTreeMap<String, String>) -> bool {
    let mut current = instance.to_owned();
    let mut guard = 0;
    while let Some(parent) = parents.get(&current) {
        if parent == candidate {
            return true;
        }
        current = parent.clone();
        guard += 1;
        if guard >= 64 {
            break;
        }
    }
    false
}

fn file_path(event: &Event) -> String {
    match &event.payload {
        EventPayload::FileOpen { path, .. } => path.clone(),
        _ => event_summary(event),
    }
}

fn stable_hash(value: &str) -> u64 {
    // FNV-1a: deterministic across runs and independent of randomized hashers.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
