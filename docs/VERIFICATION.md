# Verification Engine (Phase 3.1 hardening)

`syscall verify SESSION_ID [--json]` performs **read-only forensic verification** of a recorded SYSCALL session in SQLite. It evaluates internal consistency and evidence interpretability; it **never** repairs, migrates, rewrites, checkpoints, normalizes, or completes missing evidence.

> **Not cryptographic authenticity / tamper-proofing.** Verification detects structural, relational, lifecycle, ordering, and accounting contradictions it can observe in stored evidence. It cannot prove that a database is authentic, untampered, or complete in an adversarial environment, and absence of findings is not a guarantee of authenticity.

## Read-only guarantees and scope

Verification is designed to be strictly non-mutating:

- Opens the database read-only (`query_only=ON`, foreign keys enabled for checks) and does not run migrations, recovery, repair, or WAL checkpoint/normalization.
- Must not create or modify the database file, WAL sidecar (`-wal`), SHM sidecar (`-shm`), schema, or stored session/event/state metadata as a result of verification.
- The implementation avoids creating WAL/SHM sidecars when no WAL/SHM state is present (immutable read-only open). If SQLite requires a WAL/SHM sidecar that is unavailable/unreadable for safe access, verification fails clearly with a structured/categorized error rather than silently mutating evidence.
- Read-only behavior is enforced by implementation constraints and validated by deterministic tests using byte/hash and filesystem-metadata comparisons before and after verification (including read-only-directory cases where SQLite permits verification).

WAL handling is conservative: verification reads committed state as visible through a safe read-only open and does not checkpoint or alter WAL state.

## What is checked (defensible, read-only)

Checks are bounded and performed without full-table loads into unbounded memory:

- **Database/schema integrity:** `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, schema/user_version readability, required tables/columns presence, and unsupported-schema detection.
- **Session existence/state:** session row presence, valid/known lifecycle status, timestamp sanity/order, finalization/termination metadata consistency, recovery metadata consistency, and explicit treatment of incomplete/interrupted/recovered/still-recording/starting states.
- **Event evidence scan (bounded pagination):** deterministic ordered scan (`timestamp_ns ASC, monotonic_ns ASC, id ASC`) with duplicate-id detection, ordering/tie-breaker consistency checks, row-count reconciliation against committed counts, and scan-failure handling (`unable_to_verify` when required checks cannot be completed).
- **Event/provenance/identity sanity:** event type validity, timestamp validity, payload JSON parseability, canonical identity/process-instance consistency, raw/observer/provenance field validity, source-tracepoint vs event-type consistency, and wire-schema/provenance consistency where recorded.
- **Activity semantics (Phase 5):** `file_open` and `network_connect` rows are checked for payload-kind/type agreement, source tracepoint (`syscalls/sys_exit_openat` / `syscalls/sys_exit_connect`), wire schema >= 3, raw-result/success/errno consistency, address-family/address-length validity, port consistency, and the no-established-connection claim. Paths are checked for length/NUL validity and truncation metadata. Missing, unresolved, or provisional attribution is distinguished from contradictory/corrupt attribution; legacy unavailable provenance/accounting is treated as limited evidence, not fabricated corruption.
- **Forensic accounting/reconciliation:** committed row counts vs persisted/accounting counters, derived/counter consistency, and explicit reporting of nonzero ring-buffer/userspace loss, rejection/failure counters, and unavailable legacy accounting.

Unsupported or future schema versions: when the schema version is readable, verification produces an `unable_to_verify` report with stable finding code `DB_SCHEMA_UNSUPPORTED` without querying unknown structures or migrating. If basic inspection is impossible, verification returns a clearly documented, stable categorized error.

## Findings, assessments, and exit codes

Each finding has a stable `code`, severity (`info`, `warning`, `error`, `critical`), title/detail, evidence context, and recommendation. Finding codes are intended to be stable for automation; details/evidence strings may be refined.

Overall assessment:

- `valid` — internally consistent where checked; no error/critical findings.
- `valid_but_incomplete` — consistent where checkable, but evidence is incomplete/limited (e.g. recovered/incomplete sessions, recorded loss, unavailable legacy/provisional/unresolved evidence, bounded scan/truncation limits).
- `warning` — notable warnings/limitations without hard contradictions.
- `invalid` — contradictory, corrupt, or invalid evidence/state detected.
- `unable_to_verify` — required checks could not be completed sufficiently (e.g. unreadable/corrupt structures preventing required inspection, scan failure, or unsupported schema semantics).

Exit-code contract (`syscall verify`):

| Exit | Assessment |
|---:|---|
| `0` | `valid` |
| `2` | `valid_but_incomplete` or `warning` |
| `3` | `invalid` |
| `4` | `unable_to_verify` |

Assessments are computed deterministically from findings/scan completeness: contradictions/corruption (error/critical) take precedence as `invalid`; inability to complete required checks yields `unable_to_verify`; otherwise warnings are classified as `valid_but_incomplete` or `warning` based on limitation semantics.

## Bounded scan and reporting limits

- Events are scanned in deterministic paged batches (no unbounded full-session materialization).
- Findings are bounded; if limits are exceeded, truncation is reported explicitly (`FINDINGS_TRUNCATED` / scan-truncation findings) and the report remains interpretable as limited rather than silently complete.
- Large synthetic sessions are validated to verify without unbounded memory growth and without reporting corruption absent contradictory evidence.

### Phase 5 finding codes

| Code | Severity | Meaning |
| --- | --- | --- |
| `EVENT_PAYLOAD_TYPE_MISMATCH` | error | Activity event type carries the wrong payload variant |
| `EVENT_ACTIVITY_RESULT_INCONSISTENT` | error | `success` disagrees with the raw result |
| `EVENT_ACTIVITY_ERRNO_INCONSISTENT` | error | Successful event has errno, or failed errno != `-result` |
| `EVENT_FILE_TRACEPOINT_INCONSISTENT` | error | File event did not come from `syscalls/sys_exit_openat` |
| `EVENT_NETWORK_TRACEPOINT_INCONSISTENT` | error | Network event did not come from `syscalls/sys_exit_connect` |
| `EVENT_ACTIVITY_WIRE_SCHEMA_INCONSISTENT` | error | Activity event claims a pre-v3 wire schema |
| `EVENT_FILE_PATH_INVALID` | error | Path exceeds 256 bytes or contains NUL |
| `EVENT_FILE_TRUNCATION_INCONSISTENT` | warning | Truncation flag is set but the path is short |
| `EVENT_NETWORK_ADDRESS_INVALID` | error | Address is not valid for the declared family |
| `EVENT_NETWORK_SOURCE_INCONSISTENT` | error | Source address and port presence disagree |
| `EVENT_NETWORK_PORT_INVALID` | warning | Destination or source port is zero |
| `EVENT_NETWORK_ESTABLISHED_CLAIM` | error | Event claims an established connection |

## Limitations

- Verification is not a complete proof of runtime correctness, kernel capture correctness, or adversarial tamper evidence.
- Activity verification checks internal consistency of recorded payloads. It cannot prove the kernel hook fired, that no open/connect was missed, or that a path resolved to the file ultimately accessed.
- It cannot recover missing events/provenance, and it does not reinterpret unknown future semantics.
- Some conditions depend on SQLite behavior and local filesystem/journaling state (e.g. sidecar requirements for WAL-backed databases); such cases must fail clearly rather than mutate evidence.
- Live/privileged kernel eBPF capture validation is outside this non-privileged verification path.
