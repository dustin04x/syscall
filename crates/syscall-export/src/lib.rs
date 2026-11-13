use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use syscall_storage::Storage;

pub const EXPORT_FORMAT_VERSION: &str = "syscall-export/v2";
pub const MANIFEST_VERSION: &str = "2";
const EXPORT_COMPONENTS: [&str; 6] = [
    "metadata",
    "session",
    "process_instances",
    "events",
    "analysis",
    "verification",
];

#[derive(Debug, Clone)]
pub struct ExportRequest {
    pub session_id: String,
    pub output: PathBuf,
    pub force: bool,
    pub database_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ExportOutcome {
    pub output: PathBuf,
    pub format_version: String,
    pub bytes_written: usize,
    pub sha256_manifest: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    pub component: String,
    pub format: String,
    pub version: String,
    pub sha256: String,
    pub byte_length: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiedComponent {
    pub component: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub expected_byte_length: usize,
    pub actual_byte_length: usize,
    pub valid: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportVerification {
    pub format_version: String,
    pub manifest_version: String,
    pub valid: bool,
    pub components: Vec<VerifiedComponent>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn export_json(storage: &Storage, request: ExportRequest) -> Result<ExportOutcome> {
    validate_output_path(&request.output)?;
    if request.output.exists() && !request.force {
        return Err(anyhow!(
            "output file already exists: {} (use --force to overwrite)",
            request.output.display()
        ));
    }

    let session = storage
        .get_session(&request.session_id)
        .with_context(|| format!("could not read session {}", request.session_id))?
        .ok_or_else(|| anyhow!("session not found: {}", request.session_id))?;

    // Read-only verification: include result or an explicit failure outcome.
    // For deterministic export of identical recorded evidence, normalize the
    // verification timestamp (a property of the verification act) to 0 in the
    // embedded report; the export's own timestamp is recorded in metadata.
    let (verification_report, verification_limitation) =
        match storage.verify_session(&request.session_id) {
            Ok(mut report) => {
                report.verification_timestamp_ns = 0;
                (serde_json::to_value(report)?, None)
            }
            Err(err) => (
                json!({
                    "session_id": request.session_id,
                    "status": "verification_failed",
                    "error": err.to_string(),
                    "verification_timestamp_ns": 0
                }),
                Some(format!("verification could not be completed: {err}")),
            ),
        };

    let processes = storage
        .list_process_instances(&request.session_id)
        .context("could not derive process instances")?;
    let events = storage
        .load_all_events_for_export(&request.session_id)
        .context("could not load events for export")?;

    // Versioned optional-analysis component. Analysis is read-only; if it cannot
    // complete, an explicit failed object and limitation are still exported.
    let (analysis_component, analysis_limitation) = match syscall_analysis::analyze(
        storage,
        &request.session_id,
        syscall_analysis::AnalysisOptions::default(),
    ) {
        Ok(report) => (serde_json::to_value(report)?, None),
        Err(err) => (
            json!({
                "schema_version": syscall_core::ANALYSIS_SCHEMA_VERSION,
                "session_id": request.session_id,
                "status": "analysis_failed",
                "error": err.to_string(),
                "findings": [],
                "limitations": ["Behavioral analysis could not be completed; no findings are claimed."],
            }),
            Some(format!("behavioral analysis could not be completed: {err}")),
        ),
    };

    // Accounting/loss counters and provenance are included via session/events/provenance fields.
    // Explicit limitations: never omit known limitations silently.
    let mut limitations = vec![
        "Exported package integrity can be checked via the SHA-256 manifest after creation; this is not proof the original database was authentic or untampered before export.".to_owned(),
        "No digital signatures or chain-of-custody guarantees are provided.".to_owned(),
        "Verification, when included, is read-only and does not prove cryptographic authenticity or tamper-proofing.".to_owned(),
        "Recorded events may be incomplete when losses, drops, recovery, or unresolved identity occurred; consult accounting/loss counters and verification findings.".to_owned(),
    ];
    if let Some(l) = verification_limitation {
        limitations.push(l);
    }
    if let Some(l) = analysis_limitation {
        limitations.push(l);
    }
    if session.status.as_str() == "recovered" {
        limitations.push("Session was recovered after abnormal termination; missing in-flight evidence cannot be reconstructed.".to_owned());
    }
    if session.ringbuf_lost_events > 0
        || session.userspace_dropped_events > 0
        || session.dropped_events > 0
    {
        limitations.push("Event loss/drop counters are non-zero; exported events do not represent all runtime activity.".to_owned());
    }
    // Legacy provenance note
    let legacy_provenance = events.iter().any(|e| e.provenance.is_none());
    if legacy_provenance {
        limitations.push("Some events lack provenance metadata (legacy/unavailable); no provenance was fabricated.".to_owned());
    }
    limitations.sort();
    limitations.dedup();

    let export_timestamp_ns = syscall_core::clock::realtime_now_ns().unwrap_or(0);

    // Components for manifest: deterministic JSON bytes of each logical component.
    let metadata_component = json!({
        "export_format_version": EXPORT_FORMAT_VERSION,
        "syscall_version": env!("CARGO_PKG_VERSION"),
        "syscall_build": option_env!("SYSCALL_BUILD_INFO").unwrap_or("unknown"),
        "export_timestamp_ns": export_timestamp_ns,
        "database_path": request.database_path.display().to_string(),
        "session_id": request.session_id,
        "limitations": limitations,
    });
    let session_component = serde_json::to_value(&session)?;
    let processes_component = serde_json::to_value(&processes)?;
    let events_component = serde_json::to_value(&events)?;
    let verification_component = verification_report;

    // Build deterministic component bytes (stable key ordering via sorted maps where needed is handled
    // by serde_json's default map ordering? serde_json preserves insertion order for Map but not for
    // arbitrary structs unless configured; however we need deterministic serialization of evidence content.
    // Use canonical-ish approach: serialize with stable formatting and rely on struct field order + sorted
    // arrays we control. For reproducibility across runs, we emit pretty JSON consistently.
    let components: Vec<(&str, &str, &str, &Value)> = vec![
        ("metadata", "application/json", "1", &metadata_component),
        ("session", "application/json", "1", &session_component),
        (
            "process_instances",
            "application/json",
            "1",
            &processes_component,
        ),
        ("events", "application/json", "1", &events_component),
        (
            "analysis",
            "application/json",
            syscall_core::ANALYSIS_SCHEMA_VERSION,
            &analysis_component,
        ),
        (
            "verification",
            "application/json",
            "1",
            &verification_component,
        ),
    ];

    let mut manifest_entries = Vec::new();
    let mut component_records = Map::new();
    for (name, format, version, value) in &components {
        let bytes = canonical_json_bytes(value)?;
        let (sha256, len) = sha256_bytes(&bytes);
        manifest_entries.push(ManifestEntry {
            component: (*name).to_owned(),
            format: (*format).to_owned(),
            version: (*version).to_owned(),
            sha256,
            byte_length: len,
        });
        component_records.insert((*name).to_owned(), (*value).clone());
    }
    // Ensure deterministic manifest ordering.
    manifest_entries.sort_by(|a, b| a.component.cmp(&b.component));

    let final_manifest = manifest_entries.clone();
    let manifest_value = json!({
        "manifest_version": MANIFEST_VERSION,
        "hash_algorithm": "sha256",
        "entries": final_manifest,
        "note": "SHA-256 digests cover the canonical JSON bytes of each listed component as included in this export; the manifest is not hashed into itself. This provides post-export integrity checking, not proof of pre-export database authenticity.",
    });

    let package = json!({
        "export_format_version": EXPORT_FORMAT_VERSION,
        "manifest": manifest_value,
        "metadata": metadata_component,
        "session": session_component,
        "process_instances": processes_component,
        "events": events_component,
        "analysis": analysis_component,
        "verification": verification_component,
    });

    let out_bytes = canonical_json_bytes(&package)?;
    let bytes_written = atomic_write_restrictive(&request.output, &out_bytes, request.force)?;

    Ok(ExportOutcome {
        output: request.output,
        format_version: EXPORT_FORMAT_VERSION.to_owned(),
        bytes_written,
        sha256_manifest: final_manifest,
    })
}

/// Verify an exported package without modifying it.
///
/// v2 manifests contain only component entries. Legacy v1 packages may contain
/// a self-referential `manifest` entry; those packages are reported with a
/// warning because that one digest cannot describe the final manifest bytes.
pub fn verify_export_json(path: impl AsRef<Path>) -> Result<ExportVerification> {
    let bytes = fs::read(path.as_ref())
        .with_context(|| format!("could not read export {}", path.as_ref().display()))?;
    let package: Value = serde_json::from_slice(&bytes).context("export is not valid JSON")?;

    let format_version = package
        .get("export_format_version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("export is missing export_format_version"))?
        .to_owned();
    let manifest = package
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("export is missing manifest object"))?;
    let manifest_version = manifest
        .get("manifest_version")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("manifest is missing manifest_version"))?
        .to_owned();
    let entries: Vec<ManifestEntry> = serde_json::from_value(
        manifest
            .get("entries")
            .cloned()
            .ok_or_else(|| anyhow!("manifest is missing entries"))?,
    )
    .context("manifest entries are invalid")?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut components = Vec::new();
    let mut seen = std::collections::HashSet::new();

    match (format_version.as_str(), manifest_version.as_str()) {
        ("syscall-export/v2", "2") => {}
        ("syscall-export/v1", "1") => warnings.push(
            "legacy v1 manifest may contain a self-referential manifest entry; only component entries are verifiable"
                .to_owned(),
        ),
        _ => errors.push(format!(
            "unsupported export/manifest version {format_version:?}/{manifest_version:?}"
        )),
    }

    for entry in &entries {
        if !seen.insert(entry.component.clone()) {
            errors.push(format!(
                "duplicate manifest entry for {:?}",
                entry.component
            ));
            continue;
        }
        if entry.component == "manifest" {
            warnings.push(
                "manifest contains a legacy self-entry; its digest cannot describe the final manifest bytes"
                    .to_owned(),
            );
            continue;
        }
        let Some(component) = package.get(&entry.component) else {
            errors.push(format!(
                "manifest references missing component {:?}",
                entry.component
            ));
            continue;
        };
        let component_bytes = canonical_json_bytes(component)?;
        let (actual_sha256, actual_byte_length) = sha256_bytes(&component_bytes);
        let valid = actual_sha256 == entry.sha256 && actual_byte_length == entry.byte_length;
        if !valid {
            errors.push(format!(
                "component {:?} does not match its manifest digest/length",
                entry.component
            ));
        }
        components.push(VerifiedComponent {
            component: entry.component.clone(),
            expected_sha256: entry.sha256.clone(),
            actual_sha256,
            expected_byte_length: entry.byte_length,
            actual_byte_length,
            valid,
        });
    }

    for expected in EXPORT_COMPONENTS {
        if !seen.contains(expected) {
            errors.push(format!(
                "manifest is missing required component {expected:?}"
            ));
        }
    }

    Ok(ExportVerification {
        format_version,
        manifest_version,
        valid: errors.is_empty(),
        components,
        errors,
        warnings,
    })
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = serde_json::to_string_pretty(value)?;
    out.push('\n');
    Ok(out.into_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> (String, usize) {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    (hex, bytes.len())
}

fn validate_output_path(path: &Path) -> Result<()> {
    let s = path.to_string_lossy();
    if s.is_empty() {
        return Err(anyhow!("output path must not be empty"));
    }
    // Basic traversal/safety: disallow creating files with NUL; require a filename component.
    if s.contains('\0') {
        return Err(anyhow!("output path contains NUL byte"));
    }
    if path.file_name().is_none() {
        return Err(anyhow!("output path must include a file name"));
    }
    Ok(())
}

fn atomic_write_restrictive(path: &Path, bytes: &[u8], force: bool) -> Result<usize> {
    if path.exists() && !force {
        return Err(anyhow!(
            "output file already exists: {} (use --force to overwrite)",
            path.display()
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        return Err(anyhow!(
            "output directory does not exist: {}",
            parent.display()
        ));
    }

    // Temporary file in same directory for atomic rename.
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("output file name must be valid UTF-8"))?;
    let tmp_name = format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = parent.join(tmp_name);

    // Create with restrictive permissions.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut file = match opts.open(&tmp_path) {
        Ok(f) => f,
        Err(e) => {
            return Err(anyhow!(
                "failed to create temporary export file {}: {e}",
                tmp_path.display()
            ))
        }
    };
    if let Err(e) = file.write_all(bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!("failed to write export data: {e}"));
    }
    if let Err(e) = file.sync_all() {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!("failed to fsync export data: {e}"));
    }
    drop(file);
    // Ensure mode even if umask interfered (best effort).
    let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));

    // Respect overwrite protection: if not forcing, do not replace an existing target.
    // (We checked above; re-check to narrow race.)
    if path.exists() && !force {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!(
            "output file already exists: {} (use --force to overwrite)",
            path.display()
        ));
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!("failed to atomically rename export file: {e}"));
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    // Best-effort fsync of directory for durability.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(bytes.len())
}
