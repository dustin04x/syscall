# SYSCALL

**SYSCALL** is a Linux process intelligence / runtime forensics project focused on *real* kernel telemetry (no synthetic/mock event pipelines presented as reality). It collects process lifecycle events from eBPF tracepoints, normalizes them in userspace, persists them to SQLite, and exposes inspection via a CLI.

> **Scope (Mission 01):** intentionally narrow and honest — only `process_exec`, `process_fork`, and `process_exit` are collected from stable scheduler tracepoints (`sched_process_exec`, `sched_process_fork`, `sched_process_exit`). `file_open`/`network_connect` exist as schema placeholders and are not collected/persisted in Mission 01.

## Current status (honest)

| Area | Status | Notes |
|---|---|---|
| Non-privileged quality gate | **PASS (in this workspace)** | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo build -p syscall-cli`, and `scripts/check.sh` passed (includes eBPF object build/skeleton generation and BTF tracepoint layout checks). |
| Real kernel BPF load/attach/capture | **NOT revalidated by the agent** | Requires root / `CAP_BPF`+`CAP_PERFMON` (or equivalent). Previous privileged WSL2 runs showed BPF load/attach and namespace correlation working, but Mission 01 stabilization changes must be proven again by a privileged end-to-end run. |
| Identity integrity (raw ↔ observer ↔ canonical) | **Implemented + unit-tested; live e2e pending** | Canonical/observer-visible identity is enforced for persisted exec/exit events when correlation is known; fork uses safe provisional/buffered handling before child exec/canonical correlation. Needs privileged e2e proof. |
| Graceful SIGINT/SIGTERM handling | **Implemented + unit-tested; live e2e pending** | EINTR during ring-buffer polling is handled safely when shutdown is requested; recorder interruptions finalize as interrupted and return `130` (SIGINT) / `143` (SIGTERM). Needs privileged e2e proof. |

**Mission 01 is not complete** until process identity integrity and graceful interruption are proven by a live, privileged end-to-end test.

## What Mission 01 does

- Attaches C eBPF tracepoint programs (libbpf-rs skeleton): `sched_process_exec`, `sched_process_fork`, `sched_process_exit`.
- Sends fixed-size, versioned samples through a BPF ring buffer (4 MiB).
- Decodes every field defensively; malformed samples are counted and discarded (never panic the recorder).
- Uses `ns_tgid` (observer/collector PID-namespace TGID via `bpf_get_ns_current_pid_tgid` + configured observer PID namespace map) to correlate events when BPF and userspace observe different PID namespace ID spaces (common on WSL2/rootless/container setups).
- Attributes **target-tree** scope in userspace using tracked lineage/procfs ancestry. Tracepoints are system-wide; attribution is explicit and does not weaken scope filtering.
- Tracks PID reuse with boot-scoped process-instance IDs (`boot_id:pid:start_time_ticks`, with explicit fallback when start time is unavailable).
- Persists sessions and events to SQLite in batched transactions with schema versioning and restrictive permissions.
- Exposes CLI commands: `info`, `record`, `sessions`, `inspect`, `events`.
- Drops root privilege after loading/attaching BPF (when started via sudo), before creating the database or spawning the target, so recordings are owned by the invoking user.

## Key design: identity model (important)

SYSCALL distinguishes three identity spaces:

1. **Raw BPF identity** — kernel/BPF-observed identifiers from the event header/context (`pid/tgid/tid/ppid`, etc.). May be in a different PID namespace than the collector’s observer `/proc`.
2. **Observer-visible identity** — identifiers visible in the collector’s own `/proc`/PID namespace. When available, this is correlated from `ns_tgid` (and validated/canonicalized in userspace scope/procfs logic).
3. **Canonical process identity** — the application identity used consistently for attribution, relationships, storage, inspection, and process-instance IDs.
   - When namespace correlation/observer identity is established, **canonical = observer-visible**. `Event.pid/tid/ppid` and `process_instance_id` are persisted in that canonical space.
   - Raw BPF IDs are retained as diagnostic detail (e.g., `raw_bpf` debug identity chain; `ProcessExec.old_pid` remains a BPF detail).

### Fork handling (current limitation + safe behavior)

The BPF fork handler currently emits child `ns_tgid=0` (wire layout unchanged). Because raw child TGID may not equal observer-visible PID across namespaces, SYSCALL **does not fabricate** canonical fork identity:
- If child `ns_tgid` is available, it is used.
- Otherwise it may attempt a *verified* procfs fallback only when safe (same-namespace/process-leader evidence matches tracked canonical parent).
- If still unresolved, the fork is registered as **provisional** (lineage-admitted only; scope not weakened) and **buffered in memory** — not persisted with guessed canonical identity.
- When a later child exec/exit arrives with child-context `ns_tgid`, the provisional identity is upgraded to canonical observer identity, the raw→canonical alias is learned, and the buffered fork is flushed **before** the current event with the same canonical `process_instance_id` and original fork timestamps.
- If correlation is never observed before session end, unresolved buffered forks are flushed with explicit raw/provisional identity (honest limitation, no fabrication).

PID-reuse protection is preserved (boot-scoped instance IDs, start-time checks, no admission by name/path).

## Schema versions

These are intentionally separate:

| Contract | Version | Where |
|---|---:|---|
| BPF ring-buffer **wire schema** | `2` (decoder accepts `1`/`2`) | `ebpf/syscall_event.h` (`SYSCALL_EVENT_VERSION`), `syscall-collector::event_decoder::WIRE_SCHEMA_VERSION` |
| Core/domain/session event-payload schema | `1` | `syscall-core::event::SCHEMA_VERSION`, session/storage model |
| SQLite schema (`PRAGMA user_version`) | `1` | `syscall-storage` migrations (`001_initial.sql`) |

`syscall info` reports core and BPF wire schema separately to avoid confusion.

## Requirements

- Linux x86_64 with BPF, BTF, tracefs, and ring-buffer-capable kernel (>= 5.8 typical).
- Rust stable toolchain (workspace MSRV declared in `Cargo.toml`; tested with recent stable).
- `clang`, libbpf headers/library, `pkg-config` (for eBPF build/skeleton generation). No `bpftool` required for the normal build path.
- Privileges **only** for `syscall record`: root or `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN` on older setups). Inspection commands do not require privilege.

## Build

```bash
cargo build --workspace
# release
cargo build --release
# CLI only
cargo build -p syscall-cli
```

Standalone eBPF object + section check:

```bash
make -C ebpf clean check
```

## Non-privileged quality gate (no sudo)

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# full local gate used by this repo (includes ebpf/skeleton/BTF checks)
./scripts/check.sh
```

## Quick start

Inspect environment (no privilege):

```bash
target/debug/syscall info
# JSON
target/debug/syscall info --json
```

Record a target tree (**operator runs this manually with privilege; SYSCALL never invokes sudo/prompts for passwords**):

```bash
sudo target/debug/syscall record -- /usr/bin/sleep 5
```

Inspect as a normal user:

```bash
target/debug/syscall sessions
target/debug/syscall inspect <SESSION_ID>
target/debug/syscall events <SESSION_ID>
# JSON/examples
target/debug/syscall sessions --json
target/debug/syscall inspect <SESSION_ID> --json
target/debug/syscall events <SESSION_ID> --type process_exec --json
```

Useful variants:

```bash
# Target tree (default semantics)
sudo target/debug/syscall record --scope target-tree -- /usr/bin/sleep 5

# System-wide lifecycle observation
sudo target/debug/syscall record --scope system -- /usr/bin/sleep 5

# Redact target arguments
sudo target/debug/syscall record --redact-args -- /usr/bin/curl https://example.com

# Explicit DB/session
sudo target/debug/syscall record --db /tmp/syscall.db --session-id demo-1 -- /bin/true
```

### Exit codes (record)

- Mirrors the target’s exit code when recording succeeds and the recorder was not interrupted.
- Recorder interruption: **130** for SIGINT (`Ctrl+C`), **143** for SIGTERM (conventional `128 + signal`).
- Signalled target: `128 + target_signal` (when applicable).
- Recording/finalization failures return non-zero with an error.

On interruption, the recorder stops accepting work, handles ring-buffer polling `EINTR` safely when shutdown is requested, performs a best-effort drain, flushes/finalizes the session as `interrupted` (or accurately reported equivalent), cleans up BPF/target resources, and exits with the signal-appropriate code.

## Privileged end-to-end validation (manual, operator-run)

> **Do not run via automation that assumes sudo access.** Run manually when you have the required privileges.

```bash
cd ~/code/syscall   # or your checkout path
cargo build -p syscall-cli
sudo env RUST_LOG=debug scripts/e2e-root.sh 2>e2e-debug.log
```

What to verify after a privileged run:
- BPF loads/attaches; events are real kernel telemetry (not synthetic).
- Identity chain is consistent when `ns_tgid` correlation is present (`raw_bpf -> ns_tgid/canonical -> persisted` in debug logs); no duplicate processes caused only by raw vs observer PID differences; exec/exit share the same `process_instance_id` for a process instance.
- Target-tree scope contains target lineage only (system-wide BPF observation is filtered in userspace; harness helpers may appear in debug logs as rejected, but must not be persisted/attributed).
- Interrupt test: exit `130`, session `interrupted` and inspectable, DB valid, target cleaned up (no orphan). No fatal `BPF runtime error: Interrupted system call` when shutdown was requested.
- `syscall info` shows **core schema** and **BPF wire schema** separately.

Optional manual checks:
```bash
# send SIGTERM to a running recorder (confirm 143) — do only if appropriate
# syscall sessions / inspect / events for recorded sessions
```

## Project structure

| Path | Purpose |
|---|---|
| `ebpf/syscall.bpf.c` | C eBPF tracepoint programs, ring buffer, loss/helper stats maps |
| `ebpf/syscall_event.h` | Fixed wire format shared with Rust decoder (wire v2) |
| `ebpf/Makefile` | Standalone eBPF compile/check |
| `crates/syscall-core/` | Domain model, schema/validation, IDs (PID-reuse), scope vocabulary, clocks, paths |
| `crates/syscall-storage/` | SQLite schema/migrations, batched inserts, read-only queries |
| `crates/syscall-collector/` | BPF skeleton load/attach, strict decoder, scope/identity, procfs, writer, orchestration, signals |
| `crates/syscall-cli/` | Clap CLI, text/JSON rendering, exit-code policy |
| `scripts/check.sh` | Non-privileged quality gate |
| `scripts/e2e-root.sh` | Operator-run privileged end-to-end test (requires sudo) |
| `scripts/check-btf-layout.sh` | Tracepoint context layout check against kernel BTF |
| `scripts/env-audit.sh` | Read-only environment audit (no sudo) |
| `docs/` | Architecture, event schema, WSL compatibility, security, development, roadmap |

## Security / safety properties

- No automatic privilege escalation and no password handling.
- BPF load/attach occur while privileged; process drops to invoking user (sudo context) before DB creation/target spawn; DB directory/file use restrictive permissions.
- SQL uses bound parameters; decoder is strict/bounds-checked; kernel strings/control chars are handled defensively (escaped in terminal output).
- Bounded queues/ring-buffer handling; malformed samples and drops/loss are counted.
- Target-tree scope is enforced by userspace attribution logic and must **not** be weakened to “make events appear.” Unknown/unverifiable identities are not fabricated as canonical.
- Only process-lifecycle telemetry is collected in Mission 01; `--redact-args` can avoid persisting target arguments.

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/WSL_COMPATIBILITY.md](docs/WSL_COMPATIBILITY.md).

## Known limitations / troubleshooting notes

- **Privileged e2e required for proof:** non-privileged tests and `scripts/check.sh` do not prove kernel load/attach/runtime correctness.
- **WSL2/PID namespaces:** raw BPF TGIDs may differ from observer-visible PIDs; `ns_tgid` correlation is essential. Tracefs permissions, `unprivileged_bpf_disabled`, memlock/rlimits, and BTF availability are environment-dependent (`syscall info` helps diagnose).
- **Fork `ns_tgid=0` (BPF context limitation):** canonical fork identity may be deferred until child exec/exit; unresolved forks are buffered/flushed safely without fabricating canonical IDs. A future CO-RE/task-aware BPF improvement may help (careful wire/compat review required).
- **Target-tree scope is userspace attribution, not kernel-side filtering.** Tracepoints observe system-wide; out-of-scope events are filtered and counted.
- **Timestamps:** derived wall-clock uses a captured monotonic→realtime offset; prefer `monotonic_ns` for ordering/correlation.
- **`file_open`/`network_connect` are not implemented** (schema placeholders only).
- If you hit `BPF runtime error: Interrupted system call` on interrupt, ensure you are running a build with the EINTR/shutdown handling fix and re-run privileged e2e.

## For future development (quick map)

- **Identity/scope bugs:** start at `crates/syscall-collector/src/collector.rs` (`build_event`, fork buffering/flush, identity-chain logs), `crates/syscall-collector/src/scope.rs` (provisional/alias/lineage/PID reuse), and `procfs.rs`.
- **BPF/wire changes:** coordinate `ebpf/syscall_event.h`, `ebpf/syscall.bpf.c`, `syscall-collector/src/event_decoder.rs`, and docs; preserve compatibility or document migration explicitly.
- **Signal/finalization bugs:** `syscall-collector/src/signal.rs`, ring-buffer poll loop in `collector.rs`, writer/session finalization, CLI `record_exit_code`, and `scripts/e2e-root.sh`.
- **Storage/schema changes:** add migrations; never silently reinterpret schema versions.

## License

MIT — see [LICENSE](LICENSE).
