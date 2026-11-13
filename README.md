<h1 align="center">SYSCALL</h1>

<p align="center"><strong>Runtime forensics for Linux, built on real kernel telemetry.</strong></p>

<p align="center">
  <a href="https://github.com/dustin04x/syscall/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dustin04x/syscall/actions/workflows/ci.yml/badge.svg?branch=master"></a>
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2f6f4e?style=flat-square&labelColor=1b1b19">
  <img alt="Rust 1.82+" src="https://img.shields.io/badge/rust-1.82%2B-b03a2e?style=flat-square&labelColor=1b1b19">
  <img alt="Tauri 2" src="https://img.shields.io/badge/Tauri-2-2f6f4e?style=flat-square&labelColor=1b1b19">
  <img alt="Read-only workbench" src="https://img.shields.io/badge/workbench-read--only-b03a2e?style=flat-square&labelColor=1b1b19">
</p>

<p align="center">
  Collect process lifecycle, file-open, and network-connect activity with eBPF.<br>
  Persist it as attributable evidence. Investigate it from the CLI or a read-only desktop workbench.
</p>

<p align="center">
  <img src="docs/screenshots/overview.png" alt="SYSCALL evidence overview in the new workbench" width="100%">
</p>

> **Scope, stated plainly:** SYSCALL records real kernel telemetry. It does not present mock or synthetic event pipelines as evidence. Collection covers process lifecycle, `openat(2)` attempts, and IPv4/IPv6 `connect(2)` attempts. File contents, packet payloads, DNS names, and environment variables are never captured. A successful `connect` proves an attempt, not an established session.

## Contents

- [Why SYSCALL](#why-syscall)
- [A closer look](#a-closer-look)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Validation status](#validation-status)
- [How it works](#how-it-works)
- [CLI reference](#cli-reference)
- [Schema versions](#schema-versions)
- [Security and privacy](#security-and-privacy)
- [Known limitations](#known-limitations)
- [Documentation](#documentation)
- [Repository layout](#repository-layout)
- [Development](#development)
- [License](#license)

## Why SYSCALL

| Principle | What it means in practice |
|---|---|
| **Real telemetry** | Kernel events come from seven eBPF tracepoints, through a versioned wire format and a bounds-checked decoder. Malformed samples are counted, never guessed at. |
| **Attribution, not decoration** | Raw BPF IDs, observer-visible IDs, and canonical process identities are kept distinct. PID reuse is handled with boot-scoped process-instance IDs. |
| **Evidence you can inspect** | Every persisted event keeps provenance. Sessions report collection accounting: ring-buffer loss, userspace drops, malformed records, scope filtering, and persist failures. |
| **Analysis that explains itself** | Deterministic rules A–F attach findings to supporting events and processes, with confidence, limitations, and next steps. A finding is an observation, not a verdict. |
| **Read-only investigation** | The desktop workbench has one typed Tauri IPC boundary, no SQL, no shell, no filesystem plugins, and no recording controls. The backend fixes the database and export paths. |
| **Honest edges** | Missing data stays missing. Fork identity is buffered rather than fabricated. Failed opens remain evidence. Capture coverage and known blind spots are documented. |

## A closer look

The desktop app and standalone renderer share the same React UI. These captures use the renderer's deterministic preview dataset and label the contract as `ui-preview`; they document the interface, not a live recording. Live capture validation is reported [below](#validation-status).

| Investigation summary | Behavioral analysis |
|:---:|:---:|
| <img src="docs/screenshots/investigation-summary.png" alt="Investigation summary with evidence composition and collection accounting" width="100%"> | <img src="docs/screenshots/analysis.png" alt="Behavioral analysis finding dossier with supporting events" width="100%"> |
| Identity, collection accounting, evidence composition, and verification at a glance. | Explainable findings with severity, confidence, evidence links, and related processes. |

| Session timeline | Evidence export |
|:---:|:---:|
| <img src="docs/screenshots/timeline.png" alt="Timeline with a selected file-open event and its recorded payload" width="100%"> | <img src="docs/screenshots/export-result.png" alt="Evidence export result with per-component SHA-256 manifest" width="100%"> |
| Event density over time, filtering, and full payload provenance for a selected event. | Deterministic JSON bundle with a per-component SHA-256 manifest. |

See [all eleven screens](docs/DESKTOP.md#3-screens), including the session browser, process tree, filesystem, network, verification, and export confirmation states.

## Architecture

```mermaid
flowchart LR
    target["Target process tree"] -->|tracepoints| ebpf["eBPF programs<br/>lifecycle · openat · connect"]
    ebpf -->|"4 MiB ring buffer"| collector["Collector<br/>decode · attribute · persist"]
    collector --> db[("SQLite evidence<br/>schema v5")]
    db --> cli["CLI"]
    db --> desktop["Desktop workbench<br/>read-only"]
    cli --> analysis["Analysis · verification · export"]
    desktop --> analysis
```

The collector loads and attaches the BPF programs while privileged, drops to the invoking user, then creates the database and spawns the target. Tracepoints are system-wide; target-tree scope is enforced in userspace and every filtered event is accounted for.

## Quick start

### Requirements

| Area | Requirements |
|---|---|
| **Runtime** | Linux x86_64, kernel with BPF, BTF, tracefs, and ring-buffer support (5.8+ typical) |
| **Build** | Rust 1.82+, `clang`, libbpf headers/library, `pkg-config` |
| **Desktop** | Node.js 20+, WebKitGTK 4.1, GTK 3, and the other [Tauri Linux prerequisites](docs/DESKTOP.md) |
| **Privilege** | `record` only: root or `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN` on older kernels) |

Inspection, analysis, verification, export, and the desktop workbench require no privilege.

### Build

```bash
cargo build --workspace
cargo build --release -p syscall-cli

# eBPF object and section checks
make -C ebpf clean check
```

### Capture and inspect

```bash
# Diagnose the environment without privilege
target/release/syscall info
target/release/syscall info --json

# Record a target tree (operator-run; SYSCALL never escalates privileges itself)
sudo target/release/syscall record -- /usr/bin/sleep 5

# Inspect as a normal user
target/release/syscall sessions
target/release/syscall inspect <SESSION_ID>
target/release/syscall timeline <SESSION_ID> --limit 100
target/release/syscall analyze <SESSION_ID>
target/release/syscall verify <SESSION_ID>
```

### Open the workbench

```bash
cd desktop
npm install
npm run tauri:dev              # development window
npm run tauri:build            # release bundle
npm run tauri:build -- --no-bundle
```

The release binary opens a recorded database read-only:

```bash
target/release/syscall-workbench --db="$HOME/.local/share/syscall/<session>.db"
```

## Validation status

Last validated **2026-11-13**. Status labels distinguish what has actually been exercised.

| Area | Status | Evidence |
|---|---|---|
| Non-privileged quality gate | **PASS** | `scripts/check.sh` and the GitHub Actions workflow: formatting, Clippy with `-D warnings`, workspace tests, CLI/collector builds, eBPF compile and skeleton generation, desktop build and 30 renderer tests, both frontend builds. |
| Live kernel load / attach / capture | **PASS** (operator-run, WSL2, 2026-11-10) | Privileged `scripts/e2e-root.sh` attached all seven tracepoints and persisted real lifecycle and Phase 5 sessions. |
| Identity integrity | **PASS** (live e2e + unit tests) | Exec/exit rows carried raw, observer, and canonical identity with PID-reuse-safe process instances. |
| Signal handling | **PASS** (live e2e + unit tests) | SIGINT exited `130`, finalized the session as `interrupted`, and cleaned up the target. |
| Filesystem activity | **PASS** (live e2e) | Pair-attributed `openat` events with raw paths, flags, results, errno, and explicit truncation/relative-path limits. |
| Network activity | **PASS** (live e2e) | Real IPv4 and IPv6 `connect` attempts recorded with `-111`; attempt-only semantics documented. |
| Behavioral analysis | **PASS** (offline tests) | Deterministic rules over real temporary SQLite evidence. No privileged live validation is claimed for the rule engine. |
| Desktop workbench | **PASS** (release build + WSLg run) | Launched against a real recorded session; 30 renderer tests and 8 real-SQLite service tests pass. Read-only by design. |

The Phase 5 runs persisted **72 events** (64 file opens, 1 IPv4 connect) and **315 events** (2 connects: IPv4 and IPv6). Both verified `valid` with zero findings. The CI runner's kernel BTF layout differs from the checked WSL2 kernel, so CI records that layout check as advisory; the local gate still enforces it.

## How it works

### Collection

- Three scheduler tracepoints: `sched_process_exec`, `sched_process_fork`, `sched_process_exit`.
- Four syscall tracepoints: `sys_enter_openat`/`sys_exit_openat` and `sys_enter_connect`/`sys_exit_connect`.
- Enter/exit pairs are matched in bounded LRU maps (8192 entries each). A missing side or eviction produces no event; nothing is fabricated.
- Fixed-size, versioned samples cross a 4 MiB BPF ring buffer. Decoding is strict and bounds-checked.
- `ns_tgid` correlates events when BPF and userspace see different PID namespaces, which is common on WSL2, rootless, and container hosts.
- Target-tree scope is attributed in userspace from tracked lineage and procfs ancestry. Out-of-scope events are filtered and counted, never silently dropped.

### Identity model

SYSCALL keeps three identity spaces deliberately separate:

1. **Raw BPF identity**: kernel-observed identifiers from the event header and context.
2. **Observer-visible identity**: identifiers visible in the collector's own `/proc` and PID namespace, correlated through `ns_tgid` where available.
3. **Canonical process identity**: the persisted identity used for attribution, relationships, storage, and inspection. When correlation is established, canonical equals observer-visible. Raw IDs remain diagnostic provenance.

Process instances are boot-scoped (`boot_id:pid:start_time_ticks`) so PID reuse cannot merge unrelated processes.

<details>
<summary><strong>Fork buffering and unresolved ancestry</strong></summary>

The BPF fork handler currently emits child `ns_tgid=0`; the wire layout is unchanged. Because a raw child TGID may differ from the observer-visible PID across namespaces, SYSCALL does not invent a canonical child identity:

- If child `ns_tgid` is available, it is used.
- Otherwise a verified procfs fallback may be attempted only when same-namespace, process-leader evidence matches the tracked canonical parent.
- If identity remains unresolved, the fork is registered as **provisional** (lineage-admitted only; scope is not weakened) and buffered in memory.
- A later child exec/exit with child-context `ns_tgid` upgrades the identity, learns the alias, and flushes the buffered fork before the current event with the same canonical process-instance ID and original timestamps.
- If correlation never arrives, buffered forks are flushed at session end with explicit provisional identity. The limitation is stated, not hidden.

</details>

## CLI reference

| Workflow | Commands |
|---|---|
| **Record** | `record` with `--scope target-tree\|system`, `--redact-args`, `--db`, `--session-id` |
| **Session inspection** | `sessions`, `inspect`, `events`, `processes`, `tree`, `timeline`, `files`, `connections`, `stats` |
| **Analysis and integrity** | `analyze`, `verify` |
| **Evidence package** | `export --format json --output <path>` with SHA-256 manifest |
| **Environment** | `info` |

```bash
# Process tree, timeline, and filtered activity
syscall processes <SESSION_ID>
syscall tree <SESSION_ID>
syscall timeline <SESSION_ID> --type process_exec --pid 1234 --limit 100
syscall files <SESSION_ID> --pid 1234 --result failure
syscall connections <SESSION_ID> --family ipv6 --result success --json

# Explainable findings, filtered by rule/severity
syscall analyze <SESSION_ID>
syscall analyze <SESSION_ID> --rule SYSCALL-TEMP-EXEC --json
syscall analyze <SESSION_ID> --severity high --min-confidence medium

# Deterministic export; refuses overwrite unless --force is explicit
syscall export <SESSION_ID> --format json --output ./evidence-<SESSION_ID>.json
```

**Record exit codes:** mirrors the target's exit code on success; `130` for SIGINT, `143` for SIGTERM; a signalled target yields `128 + signal`; recording/finalization failures return non-zero. On interruption the recorder stops accepting work, drains best-effort, finalizes the session accurately, and cleans up BPF and target resources.

## Schema versions

These version numbers are intentionally independent:

| Contract | Version | Location |
|---|---:|---|
| BPF ring-buffer wire schema | `3` | `ebpf/syscall_event.h`, `syscall-collector::event_decoder::WIRE_SCHEMA_VERSION` |
| Core event-payload schema | `2` | `syscall-core::event::SCHEMA_VERSION` (readable: `1`–`2`) |
| SQLite schema (`PRAGMA user_version`) | `5` | `crates/syscall-storage/migrations/001`–`005` |

`syscall info` reports the core and BPF wire schemas separately so they are never conflated.

## Security and privacy

- **No automatic escalation.** SYSCALL never invokes `sudo`, prompts for a password, or records through the desktop app.
- **Privilege is dropped early.** BPF load/attach happen while privileged; the process becomes the invoking user before creating the database or spawning the target.
- **Boundaries are narrow.** SQL uses bound parameters; decoding is strict; kernel strings and control characters are escaped for terminal output.
- **Desktop IPC is typed and minimal.** One Tauri boundary, a `core:default`-only capability, a restrictive CSP, and backend-fixed database/export paths. No SQL, shell, dialog, filesystem, or HTTP plugins.
- **Secrets are not silently collected.** `--redact-args` avoids persisting target arguments, but file paths and network destinations remain evidence.
- **Evidence is read-only in the UI.** Analysis and verification never mutate the database. Export writes only to the backend-selected destination and requires explicit confirmation to replace an existing file.

See [SECURITY.md](docs/SECURITY.md) for the full threat model and [WSL_COMPATIBILITY.md](docs/WSL_COMPATIBILITY.md) for namespace and kernel-specific behavior.

## Known limitations

| Limitation | Consequence |
|---|---|
| **Live proof requires privilege** | Unit tests and `scripts/check.sh` do not prove kernel load/attach/runtime correctness. The operator-run privileged e2e does. |
| **Namespace correlation** | Raw BPF TGIDs may differ from observer PIDs. `ns_tgid` is essential; tracefs permissions, `unprivileged_bpf_disabled`, memlock limits, and BTF availability are environment-dependent. |
| **Fork `ns_tgid=0`** | Canonical fork identity may wait for child exec/exit. Unresolved forks remain explicitly provisional. |
| **Scope is userspace attribution** | Tracepoints observe system-wide; out-of-scope events are filtered and counted, not hidden at the kernel boundary. |
| **Partial syscall coverage** | Only `openat` and `connect` are hooked. `open`, `openat2`, write/rename/unlink, `sendto`/`sendmsg`, and `accept` are not. Paths are raw; `connect` success is not an established-session claim. |
| **Timestamps** | Wall-clock time comes from a captured monotonic-to-realtime offset. Prefer `monotonic_ns` for ordering and correlation. |
| **Analysis is not a verdict** | Findings are deterministic indicators tied to recorded events. Confidence is not a calibrated probability, and missing ancestry or collection loss limits negative conclusions. |
| **Pairing loss is not separately counted** | A missing syscall enter/exit or LRU eviction yields no event; ring-buffer and userspace drops are counted separately. |
| **Workbench is unbundled and read-only** | Recording remains a CLI/operator workflow. No installer, signature, or packaged bundle is claimed. The release binary was validated with locally staged Tauri dependencies. |

## Documentation

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, identity/scope design, and invariants |
| [DESKTOP.md](docs/DESKTOP.md) | Workbench screens, command contract, security boundary, WSL2 setup |
| [INVESTIGATION.md](docs/INVESTIGATION.md) | CLI investigation workflow and query patterns |
| [ANALYSIS.md](docs/ANALYSIS.md) | Rules A–F, configuration, finding contracts, and limits |
| [VERIFICATION.md](docs/VERIFICATION.md) | Integrity checks and interpretation |
| [EVIDENCE_EXPORT.md](docs/EVIDENCE_EXPORT.md) | JSON format, deterministic output, and manifest hashing |
| [EVENT_SCHEMA.md](docs/EVENT_SCHEMA.md) | Wire and persisted event schemas |
| [SECURITY.md](docs/SECURITY.md) | Threat model, privilege handling, and data boundaries |
| [WSL_COMPATIBILITY.md](docs/WSL_COMPATIBILITY.md) | WSL2 namespaces, BTF, and troubleshooting |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Local setup, checks, and contribution workflow |
| [ROADMAP.md](docs/ROADMAP.md) | Phase history and next steps |

## Repository layout

| Path | Purpose |
|---|---|
| `ebpf/` | C eBPF programs, fixed wire format, standalone compile/check |
| `crates/syscall-core/` | Domain model, validation, identity IDs, scope vocabulary, clocks, paths |
| `crates/syscall-collector/` | BPF skeleton, decoder, attribution, procfs, writer, orchestration, signals |
| `crates/syscall-storage/` | SQLite migrations, batched inserts, read-only queries, verification |
| `crates/syscall-analysis/` | Deterministic rules, evidence context, strict config, report assembly |
| `crates/syscall-export/` | Shared JSON export and SHA-256 manifest |
| `crates/syscall-cli/` | Clap CLI, text/JSON rendering, exit-code policy |
| `desktop/` | Tauri 2 + React 19 + TypeScript read-only workbench |
| `ui/` | Standalone renderer/preview of the same workbench interface |
| `scripts/` | Quality gate, privileged e2e, BTF layout check, environment audit |
| `docs/` | Architecture, schemas, security, analysis, verification, export, desktop |

## Development

```bash
# Full non-privileged gate (also runs the eBPF and BTF checks)
./scripts/check.sh

# Individual checks
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm run build --prefix desktop
npm test --prefix desktop
npm run build --prefix ui
```

The workspace commands include the Tauri crate and therefore need the desktop prerequisites in [DESKTOP.md](docs/DESKTOP.md). Without them, `scripts/check.sh` checks the command-independent desktop service layer headlessly and reports that the GUI was skipped.

Privileged validation is intentionally manual:

```bash
cargo build -p syscall-cli
sudo env RUST_LOG=debug scripts/e2e-root.sh 2>e2e-debug.log
```

Verify that BPF loads and attaches, identity chains reconcile across namespaces, target-tree scope holds, interruption produces exit `130` with an inspectable session, and `syscall info` reports core and wire schemas separately.

**Where to start:** identity/scope work lives in `crates/syscall-collector/src/{collector,scope,procfs}.rs`; wire changes must coordinate `ebpf/syscall_event.h`, `ebpf/syscall.bpf.c`, the decoder, and docs; signal/finalization work starts in `signal.rs` and the ring-buffer poll loop; storage changes require a new migration, never a silent reinterpretation.

## License

MIT. See [LICENSE](LICENSE).

<p align="center"><sub>Record what happened. Keep the provenance. State the limits.</sub></p>
