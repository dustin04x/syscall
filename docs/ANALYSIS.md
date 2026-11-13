# Behavioral Analysis

`syscall analyze SESSION_ID` is SYSCALL's read-only behavioral analysis engine. It
reads persisted process, filesystem, and network evidence and emits explainable
findings linked to the original event row IDs.

> **Scope and disclaimer:** SYSCALL provides behavioral indicators and forensic
> assistance. It does **not** produce a definitive malware verdict, a calibrated
> probability of maliciousness, or proof of data exfiltration. Findings describe
> recorded behavior and explain why it may matter; investigators must evaluate
> them in context.

## Architecture

| Layer | Responsibility |
|---|---|
| `syscall-core` | Versioned analysis result model: findings, severity, confidence, rule metadata, evidence completeness, report schema |
| `syscall-storage` | Existing bounded read-only evidence queries (`query_timeline`, `list_process_instances`, `session_stats`, `verify_session`) |
| `syscall-analysis` | Evidence context, deterministic rules A–F, filtering, rule configuration, report assembly |
| `syscall-cli` | `analyze` command parsing, text/JSON rendering, strict config loading, optional file output |

The collector performs no analysis in the recording hot path. The analysis crate
is a separate workspace member and has no eBPF or collector dependency. All
analysis queries are read-only; the database is never migrated, updated, or
written by `analyze`.

Analysis examines only the requested session. It never executes recorded
commands and never interprets a path or command as code.

## Result schema

`syscall analyze --json` emits `syscall-analysis/v1`. Each finding includes:

- `finding_id`: deterministic for the same rule, session evidence, and primary
  identity key.
- `rule_id`, `rule_version`.
- `severity`: `informational`, `low`, `medium`, `high`, or `critical`.
- `confidence`: `low`, `medium`, or `high`.
- `title`, `explanation`, `significance`.
- `event_ids`: original persisted event row IDs.
- `supporting_events`: persisted event details in chronological order.
- `process_instance_ids` and canonical `pids`.
- `related_processes`: process-instance references used by the finding.
- `time_range`: inclusive recorded event timestamps in nanoseconds.
- `related_findings`: reserved for links between findings in the same report.
- `limitations`: finding-specific evidence limitations.
- `next_steps`: recommended investigative actions.
- `correlation`: `same_process`, `process_tree`, or `independent`.

The report also contains the session summary, evidence completeness, evaluated
rule metadata, report-level limitations, and a `truncated` flag. A report is
sorted by severity, confidence, start time, rule ID, and finding ID so output is
deterministic for identical recorded evidence.

## Severity semantics

Severity is an investigative priority, not a probability:

| Severity | Meaning |
|---|---|
| `informational` | Context or an unresolved observation that is not itself evidence of harmful behavior |
| `low` | Behavior worth noting, commonly benign |
| `medium` | A stronger behavioral indicator that merits review |
| `high` | Direct access/behavior with significant investigative weight, such as a successful credential-file open |
| `critical` | Reserved for future rules with exceptionally strong evidence; no Phase 6 rule emits it by default |

A rule result can be filtered with `--severity`, which sets an inclusive minimum.

## Confidence semantics

Confidence describes the directness and quality of the recorded evidence. It is
**not** a calibrated probability and must not be presented as one.

| Confidence | Meaning |
|---|---|
| `high` | The relevant evidence is direct, identities/ancestry are resolved, the session is complete and verification is `valid` |
| `medium` | The relevant evidence is direct, but the session has losses/ambiguity/truncation, or the rule is explicitly temporal rather than causal |
| `low` | Resolution is missing (for example a relative path), the correlation is indirect, or multiple evidence-quality limitations apply |

When a session is incomplete, unverified, or truncated, base confidence is
downgraded: `high` → `medium`, `medium` → `low`, `low` stays `low`. The report and
finding carry an explicit limitation when this happens. Missing process
ancestry, unresolved identity, ring-buffer loss, userspace drops, malformed
events, persistence failures, non-terminal session status, and event-scan
truncation all contribute to reduced confidence.

`evidence.status` is `complete` only when all of the following hold:

- The session status is `completed`.
- The persisted counters do not indicate loss/drop/recovery/incomplete identity.
- The analysis event scan was not truncated by `max_events`.
- Read-only verification completed with assessment `valid`.

Otherwise it is `incomplete`, and the specific reasons appear in
`evidence.notes` and report `limitations`.

## Rules

All rules are deterministic. They do not use machine learning, opaque scoring,
or speculative identities. Missing events are never invented.

### Rule A — `SYSCALL-SHELL-CHAIN` (v1)

**Conditions**

1. A process instance executed a known shell basename: `sh`, `bash`, `dash`,
   `zsh`, `ksh`, `fish`, or `ash`.
2. At least two descendants are linked by recorded process-instance ancestry.
3. Maximum observed depth below the shell root is at least two.

**Reports:** root process, descendant count, maximum depth, a recorded chain,
relevant exec/fork events, process references, and timeline.

**Exclusions:** one-child shells and shells whose children do not spawn further
processes. Unresolved ancestry is never filled in by name or PID guesswork.

**False positives:** build systems, package managers, service wrappers, scripts,
and interactive shells routinely create chains.

**Severity/confidence:** low; high only with resolved ancestry and complete
verified evidence.

### Rule B — `SYSCALL-TEMP-EXEC` (v1)

**Conditions**

1. A persisted `process_exec` event has a non-empty executable filename.
2. Its lexically normalized absolute path equals a configured temporary
   directory or is beneath it at a `/` component boundary.

Default directories: `/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`.

**Exclusions:** `/tmpfoo` is not treated as `/tmp`; relative and empty executable
paths are not guessed or resolved. Missing executable paths are reported as a
rule limitation.

**False positives:** installers, builds, tests, and legitimate self-updating
tools commonly execute from temporary directories.

**Severity/confidence:** medium; high with an observed absolute path and complete
evidence.

### Rule C — `SYSCALL-SENSITIVE-OPEN` (v1)

**Conditions**

A `file_open` event matches a configured sensitive path exactly or beneath it at
a component boundary. Successful opens, failed attempts, and unresolved relative
paths are grouped and reported separately. A relative path is reported only when
its basename equals a configured sensitive entry basename, and is informational.

Default sensitive paths:

- `/etc/shadow`
- `/etc/gshadow`
- `/etc/sudoers`
- `/etc/sudoers.d`
- `/etc/pam.d`
- `/etc/ssh/ssh_host_rsa_key`
- `/etc/ssh/ssh_host_ecdsa_key`
- `/etc/ssh/ssh_host_ed25519_key`
- `/root/.ssh`

**Exclusions:** an `open` event does not prove that contents were read or
written. Relative paths cannot be resolved without the process working directory
and dirfd, so the target is not confirmed.

**False positives:** authentication, backup, configuration-management, and
monitoring software legitimately accesses credential files.

**Severity/confidence:** successful credential-store opens are high; other
successful sensitive opens are medium; failed attempts are low; unresolved
relative paths are informational. Direct absolute-path findings can be high
confidence; failed attempts are medium; unresolved relative paths are low.

### Rule D — `SYSCALL-REPEATED-CONNECT` (v1)

**Conditions**

1. At least `repeated_connection_threshold` failed `network_connect` events
   (default 3) share process instance, address family, destination address,
   destination port, and raw result.
2. All attempts fit within `correlation_window_ns` (default 60 seconds).

**Exclusions:** a single failed connection is not reported. Successful connects
are not counted as failures.

**False positives:** retry loops, unavailable local services, and scanners can
produce repeated refusals.

**Severity/confidence:** medium; high when the session is complete.

### Rule E — `SYSCALL-FS-NET-CORRELATION` (v1)

**Conditions**

A `file_open` event precedes a `network_connect` event in persisted
chronological order, within `correlation_window_ns` (default 60 seconds). Same
process-instance correlation and process-tree correlation are deliberately
separate and labeled.

For process-tree correlation, ancestry must be resolved unambiguously. If a
parent PID is ambiguous because of PID reuse, no tree link is invented.

**Exclusions:** the rule never claims that a file was transmitted, that data was
exfiltrated, or that the connection carried the file's contents. Temporal
proximity does not prove causation.

**False positives:** applications routinely open configuration or library files
before making network requests.

**Severity/confidence:** low; medium confidence for direct same-process timing,
low for tree-relative timing, further reduced for incomplete evidence.

### Rule F — `SYSCALL-SHORT-LIVED-NET` (v1)

**Conditions**

1. Recorded `process_exec`, `network_connect`, and `process_exit` events exist
   for the same process instance.
2. The connection occurred after exec and before exit.
3. Exec-to-exit duration is at or below `short_lived_window_ns` (default 10
   seconds).

**Exclusions:** processes without a recorded exit are not classified, and the
report records how many were skipped. Short lifetime alone is never presented as
suspicious.

**False positives:** CLI tools, health checks, package operations, and one-shot
network utilities are naturally short-lived.

**Severity/confidence:** low; medium when all three event types are recorded;
lower for incomplete evidence.

## Configuration

`syscall analyze SESSION_ID --config PATH` loads strict JSON. Unknown fields are
rejected; configuration is never executed. Paths must be absolute and are
lexically normalized. Duplicate normalized paths and duplicate disabled rules
are rejected. Empty path lists, zero thresholds/windows, root `/` entries, and
unknown rule IDs are errors.

Safe defaults:

```json
{
  "sensitive_paths": [
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/pam.d",
    "/etc/ssh/ssh_host_rsa_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key",
    "/root/.ssh"
  ],
  "temporary_directories": ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"],
  "repeated_connection_threshold": 3,
  "correlation_window_ns": 60000000000,
  "short_lived_window_ns": 10000000000,
  "disabled_rules": [],
  "max_findings": 1000,
  "max_events": 100000
}
```

`disabled_rules` accepts rule IDs listed above. Disabled rules are skipped by
default; an explicit `--rule RULE_ID` intentionally overrides the disabled
default while still applying all bounds.

## CLI

```bash
syscall analyze <SESSION_ID>
syscall analyze <SESSION_ID> --rule SYSCALL-TEMP-EXEC
syscall analyze <SESSION_ID> --severity high
syscall analyze <SESSION_ID> --min-confidence medium
syscall analyze <SESSION_ID> --json
syscall analyze <SESSION_ID> --json --output ./analysis.json
syscall analyze <SESSION_ID> --config ./analysis.json
```

All commands accept the global `--db PATH`. `--severity` is an inclusive
minimum. `--rule`, `--severity`, and `--min-confidence` reject unknown values
with a clear error. `--output` writes mode `0600` and truncates an existing file;
the default is stdout.

Text output contains the session summary, evidence completeness, evaluated rules,
findings grouped by severity, explanations/significance, supporting event IDs and
details, relevant process tree, limitations, and recommended next steps. Text
fields are escaped/truncated before display to prevent terminal control-sequence
injection. JSON is fully structured and bounded by the same report limits.

## Export integration

`syscall export` emits `syscall-export/v2`. The package includes an `analysis`
component whose version is `syscall-analysis/v1`. It is serialized
deterministically and participates in the SHA-256 manifest like the other
components. Event IDs in the analysis component refer to the exported event rows.

If analysis cannot complete during export, the exporter includes an explicit
object with `"status": "analysis_failed"` and a recorded limitation. It never
silently omits the component or drops findings/limitations.

## Security and performance

- Read-only storage only; no migration, update, execute, or command evaluation.
- Event payloads and configuration are treated as untrusted input.
- Event scanning is bounded by `max_events`; findings by `max_findings`.
- Supporting evidence is capped per finding; shell traversal is capped at 1,000
  descendants; process-tree correlation is capped at 200 pairs.
- Rule D uses a sliding window rather than unbounded pairwise comparisons.
- Rule F groups events by process instance once instead of rescanning the event
  list for every process.
- Process-instance derivation uses the same `max_events` bound as the event scan,
  so process counts cannot exceed the analyzed evidence window. The collector's
  process-table cap bounds the number of instances.
- Human-readable output sanitizes control characters.
- Only the requested session is read; unrelated sessions are never exposed.

## Known limitations

- Behavioral rules are contextual indicators, not verdicts.
- An open event is not a read; a connect attempt is not an established session;
  no file contents or network payloads exist in the evidence.
- Relative paths cannot be resolved, and path truncation is preserved as such.
- Missing events and losses are never reconstructed; negative conclusions are
  explicitly limited.
- `related_findings` is reserved but Phase 6 does not infer cross-finding links.
- No privileged live validation is claimed for the offline analysis engine.
- Analysis does not prove authenticity of the source database; use `verify` and
  the export manifest for their documented, limited integrity checks.
