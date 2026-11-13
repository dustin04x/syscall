use std::fs;

use syscall_analysis::{AnalysisConfig, AnalysisError, RULE_TEMP_EXEC};
use tempfile::TempDir;

fn write_config(dir: &TempDir, text: &str) -> std::path::PathBuf {
    let path = dir.path().join("analysis.json");
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn strict_config_rejects_unknown_fields_and_invalid_values() {
    let dir = TempDir::new().unwrap();
    let path = write_config(
        &dir,
        r#"{"sensitive_paths":["/etc/shadow"],"temporary_directories":["/tmp"],"unknown":true}"#,
    );
    let err = AnalysisConfig::from_path(&path).unwrap_err();
    assert!(matches!(err, AnalysisError::InvalidConfig(_)));
    assert!(err.to_string().contains("unknown field"));

    for (name, text) in [
        (
            "relative path",
            r#"{"sensitive_paths":["etc/shadow"],"temporary_directories":["/tmp"]}"#,
        ),
        (
            "root temp",
            r#"{"sensitive_paths":["/etc/shadow"],"temporary_directories":["/"]}"#,
        ),
        (
            "zero threshold",
            r#"{"sensitive_paths":["/etc/shadow"],"temporary_directories":["/tmp"],"repeated_connection_threshold":0}"#,
        ),
        (
            "unknown rule",
            r#"{"sensitive_paths":["/etc/shadow"],"temporary_directories":["/tmp"],"disabled_rules":["NO-SUCH-RULE"]}"#,
        ),
        (
            "duplicate disabled rule",
            r#"{"sensitive_paths":["/etc/shadow"],"temporary_directories":["/tmp"],"disabled_rules":["SYSCALL-TEMP-EXEC","SYSCALL-TEMP-EXEC"]}"#,
        ),
    ] {
        let path = write_config(&dir, text);
        let err = AnalysisConfig::from_path(&path).unwrap_err();
        assert!(
            matches!(err, AnalysisError::InvalidConfig(_)),
            "{name}: {err}"
        );
    }
}

#[test]
fn valid_config_normalizes_paths_and_supports_disablement() {
    let dir = TempDir::new().unwrap();
    let path = write_config(
        &dir,
        r#"{
            "sensitive_paths": ["/etc/../etc/shadow", "/root/.ssh"],
            "temporary_directories": ["/tmp/", "/var/tmp"],
            "disabled_rules": ["SYSCALL-TEMP-EXEC"],
            "repeated_connection_threshold": 5,
            "correlation_window_ns": 1000000000,
            "short_lived_window_ns": 2000000000,
            "max_findings": 10,
            "max_events": 100
        }"#,
    );
    let config = AnalysisConfig::from_path(&path).unwrap();
    assert_eq!(config.sensitive_paths, vec!["/etc/shadow", "/root/.ssh"]);
    assert_eq!(config.temporary_directories, vec!["/tmp", "/var/tmp"]);
    assert!(!config.rule_enabled(RULE_TEMP_EXEC));
    assert_eq!(config.repeated_connection_threshold, 5);
    assert_eq!(config.max_findings, 10);
}
