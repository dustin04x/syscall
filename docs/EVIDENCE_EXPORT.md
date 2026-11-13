# Evidence Export Format

This document describes the deterministic JSON evidence export produced by:

```bash
syscall export <SESSION_ID> --format json --output <FILE> [--force]
```

Export is read-only with respect to the source recording database: it opens the database read-only, does not run migrations, and does not modify session/event data. The exported file is written atomically (temporary file in the destination directory, fsync, rename) with restrictive permissions (`0600` on Unix) and will not overwrite an existing file unless `--force` is provided.

## Export package structure (JSON)

Top-level fields:

- `export_format_version`: format identifier/version string (currently `syscall-export/v2`).
- `metadata`: export metadata, including:
  - `export_timestamp_ns`: time the export was produced (not part of deterministic evidence content).
  - `database_path`: source database path as provided.
  - `session_id`: exported session identifier.
  - `syscall_version`, `syscall_build`: exporter build/version information when available.
  - `limitations`: explicit list of limitations/notes (e.g. post-export integrity semantics, legacy/unavailable provenance, loss/incompleteness, verification/analysis failure to complete).
- `session`: session metadata/counters as recorded (including redacted arguments if the session recorded them as redacted). No environment variables and no unrelated sessions are included.
- `process_instances`: reconstructed process-instance evidence derived from recorded events (stable ordering).
- `events`: all recorded events in stable deterministic order `timestamp_ns ASC, monotonic_ns ASC, id ASC`, including payload and provenance metadata when available. Phase 5 `file_open` and `network_connect` events are included automatically through the generic event export; no separate filtering is required. Legacy records with unavailable provenance serialize provenance as `null` and are noted in limitations.
- `analysis`: versioned `syscall-analysis/v1` behavioral report containing session summary, evidence completeness, evaluated rule metadata, findings, limitations, and original event IDs. See [ANALYSIS.md](ANALYSIS.md). If analysis cannot complete, this component is still present with `"status": "analysis_failed"`, an error, empty findings, and a recorded export limitation. It is never silently omitted.
- `verification`: embedded read-only verification report/outcome for the session. If verification cannot complete, the export preserves an explicit failure/unavailable outcome and records a limitation rather than silently treating the session as valid. For deterministic export of identical recorded evidence, the embedded verification report's `verification_timestamp_ns` is normalized to `0` (the export action timestamp is in `metadata.export_timestamp_ns`).
- `manifest`: SHA-256 integrity manifest (see below).

## Determinism

- Evidence content is serialized deterministically (pretty JSON with stable key ordering from Rust structures, stable process/event ordering).
- Evidence components (`metadata` excluding only the export action timestamp as noted above, `session`, `process_instances`, `events`, `analysis`, `verification`) are intended to be reproducible for identical recorded evidence. Analysis output is deterministic for identical recorded evidence and configuration (export uses default analysis configuration).
- `metadata.export_timestamp_ns` reflects when the export file was created and may differ between exports of the same evidence.

## Integrity manifest and hashing

The `manifest` contains:

- `manifest_version`: manifest schema version (currently `2`).
- `hash_algorithm`: `sha256`.
- `entries`: array of entries for the exported evidence components only:
  - `component`: component name (`analysis`, `events`, `metadata`, `process_instances`, `session`, `verification`). The manifest is not hashed into itself.
  - `version`: component format/version (`2`, or `syscall-analysis/v1` for the analysis component).
  - `sha256`: lowercase hex SHA-256 digest.
  - `byte_length`: byte length of the hashed canonical bytes.
- `note`: explicit integrity semantics.

Hashing methodology:

- For each evidence component, the canonical bytes hashed are `serde_json::to_string_pretty(<component>) + "\n"` (UTF-8) of that component value as included in the package.
- The manifest is not self-hashed. It lists only the evidence components above, so a consumer can recompute each listed hash without a circular definition.

Verify a package without modifying it:

```bash
syscall verify-export <FILE> [--json]
```

The verifier checks the format, manifest version, duplicate or missing component entries, byte lengths, and SHA-256 hashes. It exits `0` when valid and `1` when invalid. Legacy v1 packages that contain a manifest self-entry are reported as warnings rather than silently accepted.

**Integrity semantics:** the manifest provides **post-export integrity checking** for the exported package contents (detecting changes to exported components after creation when hashes are recomputed the same way). It is **not** proof that the original recording database was authentic or untampered before export, and it does not constitute a digital signature or chain of custody.

## Privacy and redaction

- Session arguments are exported as recorded; if the session used `--redact-args`, redacted placeholders are preserved and original argument values are not present.
- Exported file-open paths may reveal sensitive filenames or directory structure; exported connect events reveal destination IP addresses and ports. There are no file contents, packet payloads, or DNS names in the export.
- Environment variables are never exported.
- Only the requested session's evidence is exported; unrelated sessions are not included.
- Payloads are treated as untrusted data; JSON remains valid for unusual characters, and consumers should handle fields defensively.
- Activity fields retain their recorded limitations: paths can be relative or truncated, connect events are attempts rather than established sessions, and source address/port may be `null`.

## Versioning and compatibility

`export_format_version` identifies the export package structure and is currently `syscall-export/v2`. v2 changed the manifest to stop hashing the manifest into itself and records manifest schema version `2`. The `analysis` component carries its own `schema_version` (`syscall-analysis/v1`). Existing v1 packages remain inspectable; the verifier reports their self-entry as a legacy warning. Future changes should increment the relevant version and preserve the ability to interpret/document prior exports where practical.
