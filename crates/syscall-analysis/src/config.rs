//! Strict, documented rule configuration.
//!
//! Configuration is JSON with a closed schema (`deny_unknown_fields`). The
//! engine never evaluates configuration as code and rejects unknown fields
//! instead of silently ignoring them.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{AnalysisError, Result};

pub const RULE_SHELL_CHAIN: &str = "SYSCALL-SHELL-CHAIN";
pub const RULE_TEMP_EXEC: &str = "SYSCALL-TEMP-EXEC";
pub const RULE_SENSITIVE_OPEN: &str = "SYSCALL-SENSITIVE-OPEN";
pub const RULE_REPEATED_CONNECT: &str = "SYSCALL-REPEATED-CONNECT";
pub const RULE_FS_NET_CORRELATION: &str = "SYSCALL-FS-NET-CORRELATION";
pub const RULE_SHORT_LIVED_NET: &str = "SYSCALL-SHORT-LIVED-NET";

pub const ALL_RULE_IDS: [&str; 6] = [
    RULE_SHELL_CHAIN,
    RULE_TEMP_EXEC,
    RULE_SENSITIVE_OPEN,
    RULE_REPEATED_CONNECT,
    RULE_FS_NET_CORRELATION,
    RULE_SHORT_LIVED_NET,
];

pub const DEFAULT_SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/pam.d",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/root/.ssh",
];

pub const DEFAULT_TEMPORARY_DIRECTORIES: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/shm"];

fn default_sensitive_paths() -> Vec<String> {
    DEFAULT_SENSITIVE_PATHS
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn default_temporary_directories() -> Vec<String> {
    DEFAULT_TEMPORARY_DIRECTORIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn default_repeated_connection_threshold() -> u32 {
    3
}

fn default_correlation_window_ns() -> i64 {
    60 * 1_000_000_000
}

fn default_short_lived_window_ns() -> i64 {
    10 * 1_000_000_000
}

fn default_max_findings() -> usize {
    1_000
}

fn default_max_events() -> usize {
    100_000
}

/// Closed configuration schema. All fields have safe defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisConfig {
    #[serde(default = "default_sensitive_paths")]
    pub sensitive_paths: Vec<String>,
    #[serde(default = "default_temporary_directories")]
    pub temporary_directories: Vec<String>,
    #[serde(default = "default_repeated_connection_threshold")]
    pub repeated_connection_threshold: u32,
    #[serde(default = "default_correlation_window_ns")]
    pub correlation_window_ns: i64,
    #[serde(default = "default_short_lived_window_ns")]
    pub short_lived_window_ns: i64,
    /// Rule IDs that are skipped unless explicitly requested with `--rule`.
    #[serde(default)]
    pub disabled_rules: Vec<String>,
    #[serde(default = "default_max_findings")]
    pub max_findings: usize,
    #[serde(default = "default_max_events")]
    pub max_events: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            sensitive_paths: default_sensitive_paths(),
            temporary_directories: default_temporary_directories(),
            repeated_connection_threshold: default_repeated_connection_threshold(),
            correlation_window_ns: default_correlation_window_ns(),
            short_lived_window_ns: default_short_lived_window_ns(),
            disabled_rules: Vec::new(),
            max_findings: default_max_findings(),
            max_events: default_max_events(),
        }
    }
}

impl AnalysisConfig {
    /// Load and validate a JSON configuration file.
    pub fn from_path(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|err| {
            AnalysisError::InvalidConfig(format!("could not read config {}: {err}", path.display()))
        })?;
        let text = String::from_utf8(bytes).map_err(|err| {
            AnalysisError::InvalidConfig(format!("config {} is not UTF-8: {err}", path.display()))
        })?;
        let config: Self = serde_json::from_str(&text).map_err(|err| {
            AnalysisError::InvalidConfig(format!(
                "invalid config {}: {err} (unknown fields are rejected)",
                path.display()
            ))
        })?;
        config.validate()
    }

    /// Validate all fields and normalize path lists.
    pub fn validate(mut self) -> Result<Self> {
        if self.repeated_connection_threshold == 0 {
            return Err(AnalysisError::InvalidConfig(
                "repeated_connection_threshold must be greater than zero".to_owned(),
            ));
        }
        if self.correlation_window_ns <= 0 {
            return Err(AnalysisError::InvalidConfig(
                "correlation_window_ns must be greater than zero".to_owned(),
            ));
        }
        if self.short_lived_window_ns <= 0 {
            return Err(AnalysisError::InvalidConfig(
                "short_lived_window_ns must be greater than zero".to_owned(),
            ));
        }
        if self.max_findings == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_findings must be greater than zero".to_owned(),
            ));
        }
        if self.max_events == 0 {
            return Err(AnalysisError::InvalidConfig(
                "max_events must be greater than zero".to_owned(),
            ));
        }

        self.sensitive_paths = normalize_path_list("sensitive_paths", &self.sensitive_paths)?;
        self.temporary_directories =
            normalize_path_list("temporary_directories", &self.temporary_directories)?;

        let mut seen = BTreeSet::new();
        for rule in &self.disabled_rules {
            if !ALL_RULE_IDS.contains(&rule.as_str()) {
                return Err(AnalysisError::InvalidConfig(format!(
                    "unknown disabled rule {rule:?}; expected one of: {}",
                    ALL_RULE_IDS.join(", ")
                )));
            }
            if !seen.insert(rule.clone()) {
                return Err(AnalysisError::InvalidConfig(format!(
                    "duplicate disabled rule {rule:?}"
                )));
            }
        }
        self.disabled_rules.sort();
        Ok(self)
    }

    pub fn rule_enabled(&self, rule_id: &str) -> bool {
        !self.disabled_rules.iter().any(|value| value == rule_id)
    }

    pub fn temporary_path(&self, path: &str) -> Option<String> {
        let normalized = normalize_absolute_path(path)?;
        self.temporary_directories
            .iter()
            .find(|directory| path_matches(&normalized, directory))
            .cloned()
    }

    pub fn sensitive_path(&self, path: &str) -> Option<String> {
        let normalized = normalize_absolute_path(path)?;
        self.sensitive_paths
            .iter()
            .find(|entry| path_matches(&normalized, entry))
            .cloned()
    }

    pub fn sensitive_leaf_names(&self) -> Vec<String> {
        self.sensitive_paths
            .iter()
            .filter_map(|entry| {
                PathBuf::from(entry)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .collect()
    }
}

fn normalize_path_list(name: &str, values: &[String]) -> Result<Vec<String>> {
    if values.is_empty() {
        return Err(AnalysisError::InvalidConfig(format!(
            "{name} must not be empty"
        )));
    }
    let mut out = Vec::new();
    for value in values {
        if value.as_bytes().contains(&0) {
            return Err(AnalysisError::InvalidConfig(format!(
                "{name} contains a NUL byte"
            )));
        }
        let normalized = normalize_absolute_path(value).ok_or_else(|| {
            AnalysisError::InvalidConfig(format!("{name} entry {value:?} must be an absolute path"))
        })?;
        if normalized == "/" {
            return Err(AnalysisError::InvalidConfig(format!(
                "{name} entry {value:?} is too broad (root)"
            )));
        }
        if out.contains(&normalized) {
            return Err(AnalysisError::InvalidConfig(format!(
                "{name} contains duplicate normalized path {normalized:?}"
            )));
        }
        out.push(normalized);
    }
    out.sort();
    Ok(out)
}

/// Lexically normalize an absolute path without touching the filesystem.
/// Returns `None` for relative paths, empty paths, and paths escaping root.
pub fn normalize_absolute_path(value: &str) -> Option<String> {
    if value.is_empty() || !value.starts_with('/') {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for component in Path::new(value).components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::Prefix(_) => return None,
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    Some(out)
}

/// Exact path or directory-prefix match with a component boundary.
pub fn path_matches(path: &str, entry: &str) -> bool {
    path == entry
        || path
            .strip_prefix(entry)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
