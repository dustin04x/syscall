# Roadmap

## Mission 01 — process lifecycle (current)

Delivered:

- Real exec/fork/exit tracepoint programs, ring buffer, strict decoder.
- Target-tree and system attribution with PID-reuse-safe identity.
- SQLite sessions, batched writes, indexes, schema versioning, read-only inspect.
- CLI: `info`, `record`, `sessions`, `inspect`, `events`.
- Non-privileged quality gate and reproducible BTF layout check.
- Honest WSL2 compatibility report.

Outstanding proof:

- One operator-run `sudo scripts/e2e-root.sh` to promote the blocked kernel rows
  to real PASS/FAIL.

## Mission 02 — close the privileged evidence gap

- Run the privileged e2e on WSL2 and on a native Linux host.
- Capture real exec/fork/exit output, loss counters, and Ctrl+C behavior.
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

## Mission 04 — kernel-side scope and scalability

- Add optional cgroup or PID-map filtering while preserving documented
  target-tree semantics.
- Compare kernel filtering against userspace attribution for correctness.
- Add multi-session retention, vacuum/export, and database size limits.
- Add backpressure metrics and alerting on sustained drops.

## Mission 05 — operational maturity

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
