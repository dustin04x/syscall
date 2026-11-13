# Roadmap

## Phase 1–4 — process lifecycle and investigation (delivered)

- Real exec/fork/exit tracepoint programs, ring buffer, strict decoder.
- Target-tree and system attribution with PID-reuse-safe identity.
- SQLite sessions, batched writes, indexes, schema versioning, read-only inspect.
- CLI: `info`, `record`, `sessions`, `inspect`, `events`, `processes`, `tree`,
  `timeline`, `stats`, `verify`, `verify-export`, `export`.
- Non-privileged quality gate and reproducible BTF layout check.
- Honest WSL2 compatibility report.

Privileged proof:

- Completed 2026-11-10: `scripts/e2e-root.sh` returned `E2E PASS`, including
  lifecycle capture, SIGINT handling, and user-owned database checks.

## Phase 5 — filesystem and network activity (delivered)

Delivered:

- Real `openat` file-open capture with raw path, flags, dirfd, result, success,
  errno, and explicit truncation/relative-path flags.
- Real IPv4/IPv6 `connect` attempt capture with family, destination/source,
  ports, and raw result; attempts are not reported as established connections.
- Wire schema v3, strict decoder, additive SQLite migration 4, CLI `files` and
  `connections`, verification, and deterministic export.

Privileged proof (2026-11-10):

- First session: 72 events (64 file-open, 1 IPv4 connect); second: 315 events,
  with IPv4 `127.0.0.1:1` and IPv6 `::1:1` connects, both `-111`.
- `/etc/hostname` open succeeded.
- Both sessions returned `valid` from `syscall verify` with zero findings.
- Per-event redaction rules and path allow/deny filters remain future work.

## Phase 6 — behavioral analysis and explainable detection (delivered, offline)

Delivered:

- New `syscall-analysis` crate with deterministic rules A–F over persisted
  process, filesystem, and network evidence.
- Evidence-backed findings with stable IDs, severity, confidence, event IDs,
  process-instance IDs, time ranges, limitations, and next steps.
- `syscall analyze` with rule/severity/confidence filters, strict JSON config,
  text/JSON output, and file output.
- Versioned `syscall-analysis/v1` report and optional export component under
  `syscall-export/v2`, covered by the SHA-256 manifest and a read-only
  `verify-export` command.
- Real-SQLite tests for positive/negative behavior, ambiguity, incomplete
  evidence, disabled/filtered rules, deterministic output, and read-only access.

No privileged live validation is claimed for the offline analysis engine.

## Next — close the privileged evidence gap

- Run the privileged e2e on a native Linux host (WSL2 completed 2026-11-10).
- Extend the captured baseline with stress, loss, and crash-injection cases.
- Add a privileged CI lane with explicit provisioning, never password prompts.
- Add a stress case with many short-lived children to measure ring-buffer and
  channel drops.
- Add a crash-injection test that leaves a `recording` session and verifies
  read-only inspection.
- Add an explicit follow/stop policy for detached descendants that outlive the
  launched target.

## Mission 03 — file and network telemetry

- Implement real `file_open` collection with bounded path capture and explicit
  noise controls.
- Implement real `network_connect` collection with address-family-aware capture.
- Remove the schema-only restriction only when each event has a real collector
  and kernel-run evidence.
- Add per-event redaction rules and path allow/deny filters.

## Later — kernel-side scope, scalability, and operations

- Add optional cgroup or PID-map filtering while preserving documented
  target-tree semantics.
- Compare kernel filtering against userspace attribution for correctness.
- Add multi-session retention, vacuum/export, and database size limits.
- Add backpressure metrics and alerting on sustained drops.

- Package a release binary and document capability-based installation.
- Add structured JSON logs for recorder diagnostics.
- Add tamper-evident storage (hash chain or external signing) if the threat model
  requires it.
- Add a stable schema migration matrix and upgrade/downgrade tests.
- Add export formats suitable for downstream analysis.

## Non-goals

- File contents, memory, keystrokes, or network payload capture.
- Hiding the system-wide nature of tracepoints.
- Automatic privilege escalation or password handling.
- Claiming kernel coverage from userspace or synthetic fixtures.
