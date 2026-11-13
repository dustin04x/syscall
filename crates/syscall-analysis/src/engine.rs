//! Analysis orchestration: bounded loading, deterministic rule execution,
//! filtering, and report assembly.

use std::collections::BTreeSet;

use syscall_core::{
    AnalysisConfidence, AnalysisReport, AnalysisRuleMetadata, AnalysisSeverity,
    ANALYSIS_SCHEMA_VERSION,
};
use syscall_storage::Storage;

use crate::config::{AnalysisConfig, ALL_RULE_IDS};
use crate::evidence::Evidence;
use crate::rules::{self, RuleOutcome};
use crate::{AnalysisError, Result};

#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    pub config: AnalysisConfig,
    /// When present, run only this rule. An explicit rule overrides the
    /// configured disabled-rule default, but still performs all safety bounds.
    pub rule: Option<String>,
    /// Inclusive minimum severity.
    pub min_severity: Option<AnalysisSeverity>,
    /// Inclusive minimum confidence.
    pub min_confidence: Option<AnalysisConfidence>,
}

/// Analyze one persisted session. This function performs only read-only storage
/// calls and never executes any recorded command or payload.
pub fn analyze(
    storage: &Storage,
    session_id: &str,
    options: AnalysisOptions,
) -> Result<AnalysisReport> {
    let config = options.config.validate()?;
    let rule_filter = if let Some(rule) = &options.rule {
        if !ALL_RULE_IDS.contains(&rule.as_str()) {
            return Err(AnalysisError::UnknownRule(
                rule.clone(),
                ALL_RULE_IDS.join(", "),
            ));
        }
        Some(rule.clone())
    } else {
        None
    };

    let evidence = Evidence::load(storage, session_id, &config)?;
    let all_metadata = rules::metadata();
    let selected: Vec<AnalysisRuleMetadata> = all_metadata
        .into_iter()
        .filter(|metadata| match &rule_filter {
            Some(rule) => metadata.rule_id == *rule,
            None => config.rule_enabled(&metadata.rule_id),
        })
        .collect();

    let mut findings = Vec::new();
    let mut limitations = evidence.limitations.clone();
    for metadata in &selected {
        let outcome = rules::evaluate(&metadata.rule_id, &evidence, &config)?;
        let RuleOutcome {
            findings: rule_findings,
            limitations: rule_limits,
        } = outcome;
        findings.extend(rule_findings);
        limitations.extend(rule_limits);
    }

    findings.retain(|finding| {
        options
            .min_severity
            .is_none_or(|minimum| finding.severity >= minimum)
            && options
                .min_confidence
                .is_none_or(|minimum| finding.confidence >= minimum)
    });
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(b.confidence.rank().cmp(&a.confidence.rank()))
            .then(a.time_range.start_ns.cmp(&b.time_range.start_ns))
            .then(a.rule_id.cmp(&b.rule_id))
            .then(a.finding_id.cmp(&b.finding_id))
    });

    let mut truncated = evidence.truncated;
    if findings.len() > config.max_findings {
        findings.truncate(config.max_findings);
        truncated = true;
        limitations.push(format!(
            "Findings were truncated at the configured max_findings bound ({}).",
            config.max_findings
        ));
    }

    limitations.push(
        "Analysis reports behavioral indicators from recorded evidence; it does not produce a definitive malware verdict."
            .to_owned(),
    );
    if findings.is_empty() {
        limitations.push(
            "No enabled rule produced a finding. This is not proof that the session is benign, particularly when evidence is incomplete."
                .to_owned(),
        );
    }
    let mut seen = BTreeSet::new();
    limitations.retain(|value| seen.insert(value.clone()));
    limitations.sort();

    let session_command = if evidence.session.arguments.is_empty() {
        evidence.session.command.clone()
    } else {
        format!(
            "{} {}",
            evidence.session.command,
            evidence.session.arguments.join(" ")
        )
    };
    Ok(AnalysisReport {
        schema_version: ANALYSIS_SCHEMA_VERSION.to_owned(),
        session_id: evidence.session.id.clone(),
        session_command,
        session_scope: evidence.session.recording_scope.as_str().to_owned(),
        session_started_at_ns: evidence.session.started_at_ns,
        session_ended_at_ns: evidence.session.ended_at_ns,
        evidence: evidence.completeness(),
        rules_evaluated: selected,
        findings,
        limitations,
        truncated,
    })
}
