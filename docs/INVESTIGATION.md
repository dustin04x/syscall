# Investigation Workflow

This document describes the Phase 4 CLI investigation workflow for inspecting persisted SYSCALL sessions. All investigation commands read recorded evidence from SQLite; they do not attach eBPF, do not execute recorded commands, and do not modify the source database.

## Principles

- Every displayed conclusion must be traceable to recorded events/counters in the session database.
- Missing activity is never invented. When evidence is incomplete (loss, unresolved identity/ancestry, missing parent, PID reuse ambiguity), commands report it explicitly.
- Timestamps in human-readable output are UTC. Event ordering is the stable persisted order: `timestamp_ns ASC, monotonic_ns ASC, id ASC`.
- Terminal text output escapes control characters in untrusted fields (process names, filenames, command text, etc.) to avoid escape-sequence injection. JSON output is valid UTF-8 JSON.

## Commands

All commands accept `--db <PATH>` to select a database and `--json` for machine-readable output.

### `syscall processes <SESSION_ID>`

Lists process instances observed in the session, derived from recorded events.

Reported fields (when available):

- **Process instance ID**: canonical boot-scoped identity (`boot_id:pid:start_time_ticks` or explicit fallback form when start time is unavailable). This is the identity used for investigation, not PID alone.
- **Canonical PID**: observer-visible/canonical PID recorded with events for the instance.
- **Parent PID / parent instance**: recorded parent relationship evidence. Parent instance linkage is shown only when the parent can be identified unambiguously from recorded evidence; ambiguous PID-reuse cases are left unresolved and flagged.
- **Executable / command line**: best recorded executable/exec evidence and the session target command/arguments as recorded. Redacted session arguments remain redacted (e.g. `<redacted>`); SYSCALL does not reveal arguments that were not recorded.
- **First/last observed timestamps** (UTC) and **event count**.
- **Exit observed**: whether a `process_exit` event was recorded for the instance.
- **Unresolved flags**: `identity_unresolved` and/or `ancestry_unresolved` with explanatory notes when identity, parent linkage, fork correlation, or instance start time is missing/ambiguous.

Examples:

```bash
syscall processes <SESSION_ID>
syscall --json processes <SESSION_ID>
syscall --db /path/to/syscall.db processes <SESSION_ID>
```

### `syscall tree <SESSION_ID>`

Displays a process hierarchy reconstructed from recorded process-instance evidence.

Requirements/behavior:

- Uses **process instance identity**, not PID alone, to represent nodes/relationships.
- Handles **PID reuse** by treating ambiguous parent PID matches as unresolved rather than guessing the wrong instance.
- Handles **missing parents** and **unresolved forks/identity** explicitly (`[unresolved ancestry]` markers and notes); does not invent parent relationships.
- Prevents **cycles** and reports them explicitly (`[CYCLE]`) instead of recursing infinitely.
- Distinguishes observed relationships from unresolved/ambiguous ones in text and JSON.

Examples:

```bash
syscall tree <SESSION_ID>
syscall --json tree <SESSION_ID>
```

### `syscall timeline <SESSION_ID>`

Shows a chronological event timeline from persisted evidence.

- Stable ordering: `timestamp_ns ASC, monotonic_ns ASC, id ASC`.
- Human-readable UTC timestamps, event type, process identity, and relevant event details. `file_open` rows show path, flags, dirfd/relative/truncated notes, and success/errno; `network_connect` rows show family, destination, source when available, and attempt outcome.
- Supports pagination/limits and JSON output.
- Filters operate on actual persisted evidence; unsupported filters are not silently ignored and invalid inputs return errors.

Filters:

- `--type <process_exec|process_fork|process_exit|file_open|network_connect>`
- `--pid <PID>` (canonical recorded PID)
- `--process-instance <ID>`
- `--from <TIME>` and `--to <TIME>`: Unix epoch nanoseconds (integer) or RFC3339 timestamp (e.g. `2026-01-02T03:04:05Z`)
- `--limit <N>` (default 200)
- `--offset <N>`
- `--json`

Examples:

```bash
syscall timeline <SESSION_ID>
syscall timeline <SESSION_ID> --type process_exec --limit 50
syscall timeline <SESSION_ID> --pid 1234 --from 2026-01-02T00:00:00Z --to 2026-01-02T01:00:00Z
syscall timeline <SESSION_ID> --process-instance 'boot:1234:5678' --json
```

### `syscall files <SESSION_ID>`

Displays recorded `openat(2)` attempts (successful and failed) from persisted evidence.

Fields: event id, UTC timestamp, canonical PID and process instance, comm, raw path, open flags (hex), raw result, outcome/errno, and notes for relative paths (`dirfd`) and truncation.

Filters:

- `--pid <PID>` (canonical recorded PID)
- `--process-instance <ID>`
- `--from <TIME>` / `--to <TIME>` (epoch ns or RFC3339)
- `--result success|failure`
- `--limit <N>` (default 200), `--offset <N>`, `--json`

The path is the string passed to `openat`, not a resolved absolute path. A row proves an open attempt and its return value, not that file contents were read. Truncated paths are marked; unsupported calls such as `open`, `openat2`, and relative path resolution are not captured.

```bash
syscall files <SESSION_ID>
syscall files <SESSION_ID> --pid 1234 --result failure --json
```

### `syscall connections <SESSION_ID>`

Displays recorded IPv4/IPv6 `connect(2)` attempts.

Fields: event id, UTC timestamp, canonical PID and process instance, comm, address family, source address/port when available, destination address/port, raw result, and outcome/errno.

Filters:

- `--pid <PID>`
- `--process-instance <ID>`
- `--from <TIME>` / `--to <TIME>`
- `--family ipv4|ipv6`
- `--result success|failure`
- `--limit <N>` (default 200), `--offset <N>`, `--json`

`success` means `connect(2)` returned 0, not that the connection was established, used TCP, or transferred data. The syscall tracepoint cannot distinguish TCP from UDP; source metadata is usually unavailable and is shown as such rather than guessed.

```bash
syscall connections <SESSION_ID>
syscall connections <SESSION_ID> --family ipv6 --result failure --json
```

### `syscall stats <SESSION_ID>`

Shows session-level investigation statistics derived from recorded session counters and events:

- Duration (when start/end available).
- Process instance count and event counts by type.
- Events received/decoded/attributed/persisted and scope/malformed/persist-failure counters (as recorded).
- **Kernel ring-buffer lost** and **userspace dropped** event counters.
- Unresolved identity count (process instances with unresolved identity) when available.
- Session status/termination state/reason and target exit code/signal when recorded.
- Optional verification assessment (`--verify`) computed read-only; verification is never required to inspect recorded counters.

When losses occurred or evidence is otherwise incomplete, stats explicitly state that observed counts may not represent all activity.

Examples:

```bash
syscall stats <SESSION_ID>
syscall stats <SESSION_ID> --verify
syscall --json stats <SESSION_ID> --verify
```

### `syscall analyze <SESSION_ID>`

Runs deterministic behavioral rules over persisted evidence. Analysis is
read-only, does not execute recorded commands, and does not produce a malware
verdict. See [ANALYSIS.md](ANALYSIS.md) for every rule, confidence/severity
semantics, configuration, and the versioned JSON schema.

Options:

- `--rule <RULE_ID>`: run only one rule (for example `SYSCALL-TEMP-EXEC`).
- `--severity <LEVEL>`: inclusive minimum severity.
- `--min-confidence <LEVEL>`: inclusive minimum confidence.
- `--config <FILE>`: strict JSON rule configuration.
- `--output <FILE>`: write text or JSON output to a mode-`0600` file.
- `--json`: emit the versioned `syscall-analysis/v1` report.

Examples:

```bash
syscall analyze <SESSION_ID>
syscall analyze <SESSION_ID> --rule SYSCALL-FS-NET-CORRELATION
syscall analyze <SESSION_ID> --severity high --json
syscall analyze <SESSION_ID> --config ./analysis.json --output ./analysis.txt
```

Text output includes the session summary, evidence completeness, findings grouped
by severity, explanations, supporting event IDs and details, relevant process
tree, limitations, and recommended next steps.

## Bounded operation

Investigation queries use bounded pagination/iteration and avoid loading entire large sessions into memory unnecessarily. Timeline, files, and connections queries are paged by SQL `LIMIT/OFFSET` and use a fixed total order; export loads events in fixed-size pages in stable order. `files`/`connections` filters are applied in SQL, including payload `success`/`family` filters, and never materialize the whole session.
