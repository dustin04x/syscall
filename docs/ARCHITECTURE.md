# Architecture

## Goals

SYSCALL must produce **real** process, filesystem, and network telemetry, not
simulated events. The design therefore separates five concerns:

1. Kernel collection with a minimal, verifiable eBPF surface.
2. Strict decoding of untrusted kernel samples.
3. Explicit userspace attribution of system-wide tracepoints.
4. Durable, inspectable storage with bounded memory use.
5. A CLI that works after the recorder exits and after crashes.

## Workspace layout

| Crate | Responsibility |
| --- | --- |
| `syscall-core` | Domain model, schema versions, event validation, IDs, clocks, paths, scope vocabulary |
| `syscall-storage` | SQLite schema, migrations, sessions, batched event insert, read-only queries |
| `syscall-collector` | eBPF skeleton, tracepoint programs, ring-buffer decode, scope attribution, writer, orchestration |
| `syscall-analysis` | Read-only evidence context, deterministic rules A–F, strict configuration, report assembly |
| `syscall-cli` | Clap commands, text/JSON rendering, exit-code policy |

`syscall-core` has no eBPF or SQLite dependency. `syscall-storage` has no eBPF
dependency. This keeps the event contract and database independently testable.

## Kernel side

`ebpf/syscall.bpf.c` attaches to seven stable tracepoints: three scheduler
lifecycle hooks and two syscall enter/exit pairs.

Process lifecycle:

- `tracepoint/sched/sched_process_exec`
- `tracepoint/sched/sched_process_fork`
- `tracepoint/sched/sched_process_exit`

Filesystem activity:

- `tracepoint/syscalls/sys_enter_openat` and `syscalls/sys_exit_openat`

Network activity:

- `tracepoint/syscalls/sys_enter_connect` and `syscalls/sys_exit_connect`

The syscall hooks are paired in userspace-BPF maps keyed by
`bpf_get_current_pid_tgid()`. Each of `openat_args` and `connect_args` is a
bounded `BPF_MAP_TYPE_LRU_HASH` (8192 entries). Enter stores the arguments;
exit looks up and removes the entry, so one attempt produces at most one event.
A missing enter or an LRU eviction produces no event rather than a fabricated
one. Events are emitted only at exit, carrying the raw return value, which makes
attempt-versus-success explicit. The hook does not resolve paths, perform DNS,
or inspect payloads.

It uses fixed-size local structs instead of `vmlinux.h`/CO-RE. The context
layouts were verified against the running kernel BTF and are protected by
`_Static_assert` in C and by `scripts/check-btf-layout.sh`:

| Tracepoint context | Size | Verified members |
| --- | --- | --- |
| `trace_event_raw_sched_process_exec` | 20 | `ent@0`, `__data_loc_filename@8`, `pid@12`, `old_pid@16` |
| `trace_event_raw_sched_process_fork` | 48 | `ent@0`, `parent_comm@8`, `parent_pid@24`, `child_comm@28`, `child_pid@44` |
| `trace_event_raw_sched_process_template` | 32 | `ent@0`, `comm@8`, `pid@24`, `prio@28` |

The programs write to a 4 MiB `BPF_MAP_TYPE_RINGBUF`. A one-entry array map
accumulates ring-buffer output failures so userspace can persist a real loss
counter. Not all retention failures are counted: a missing syscall enter or LRU
pairing-map eviction silently yields no activity event and is a documented gap.
The eBPF side performs no filtering and no allocations beyond fixed stack
storage; the file-open event is ring-buffer reserved because its 336-byte event
plus 272-byte pairing arguments exceed the 512-byte BPF stack limit.

The target filename in the exec tracepoint is a `__data_loc` string. The low 16
bits are an offset from the tracepoint context; `bpf_probe_read_kernel_str`
copies it with a hard 256-byte bound and the header records the actual length.

## Wire format

The wire header is 56 bytes and carries magic, wire schema version, event type,
monotonic timestamp, pid, tgid, uid, gid, comm, payload length, and the
observer-namespace `ns_tgid`. Samples are 320 bytes (exec), 96 bytes (fork),
64 bytes (exit), 336 bytes (file-open), and 104 bytes (network-connect). Wire v3
adds the activity types; v1/v2 process samples remain decodable, while activity
types require v3.

The Rust decoder never trusts lengths or strings. It checks magic, schema
version, event type, minimum sample size, payload length bounds, payload end
bounds, and NUL termination. A malformed sample is counted and discarded; it
cannot terminate the session.

## Recording phases

`syscall_collector::record` executes in phases so privilege is held for the
shortest possible time:

1. **Validate** the request, scope, target command, and session id.
2. **Inspect privilege** (`euid`, `CapEff`, `unprivileged_bpf_disabled`, BTF).
3. **Load and attach** the skeleton while root/capable.
4. **Drop privilege.** If started through sudo, `setgroups(0)`, `setgid`, then
   `setuid` to `SUDO_UID`/`SUDO_GID`, verify the drop, and set `umask 077`.
5. **Create the session** in SQLite as the invoking user.
6. **Spawn the target** in its own process group.
7. **Register the root pid** with the scope tracker.
8. **Poll** the ring buffer, decode, attribute, and enqueue into a bounded
   channel.
9. **Drain and finalize.** On target exit or signal, stop the callback, read the
   loss counter, disconnect the channel, join the writer, and write final
   status/counters.

A session row is created before the target starts. A `Drop` guard marks an
unfinished session `failed` with an explanatory error, which covers ordinary
Rust unwinds. A hard crash leaves the row in `recording`; inspection still
works. This is deliberate: forensic data must remain readable.

## Scope semantics

The kernel tracepoints are system-wide. SYSCALL does **not** install a
kernel-side PID or cgroup filter. `RecordingScope` therefore describes
userspace attribution:

- `target-tree`: include the launched target and descendants.
- `system`: include every collected event observed.

The same tracked-instance contract applies to file-open and network-connect
events. Activity attribution reads `/proc/<tgid>` (or the namespace-correlated
TGID passed by BPF), resolves the observed identity through the scope tracker,
and rejects unknown processes in target-tree mode. No activity event is
attributed to a PID merely because the number matches; start-time and lineage
checks still apply.

Target-tree attribution:

1. The spawned target is registered as the root.
2. A fork event is admitted if its parent is tracked.
3. If a fork event was lost or arrived out of order, `/proc/<ppid>` ancestry is
   walked up to 64 levels looking for a tracked ancestor.
4. Thread-creation events are rejected by checking whether
   `/proc/<child>/status` has `Tgid == Pid`; the same check handles thread exits.
5. A PID with a different `start_time_ticks` than the cached instance is treated
   as reused and is not admitted without new lineage.
6. The tracked-process table is capped at 65,536 entries. Namespace aliases and
   unresolved-fork buffering are separately capped; overflow fork entries are
   emitted as explicitly unresolved rather than silently dropped. Events for new
   processes beyond the cap are treated as filtered and counted, so a fork bomb
   cannot grow userspace memory without bound.

The scope is persisted in `sessions.recording_scope`, and `syscall info` and
`syscall inspect` show it explicitly. Kernel-side filtering is a future mission.

## Process identity

`process_instance_id = boot_id:pid:start_time_ticks`, where `start_time_ticks` is
field 22 of `/proc/<pid>/stat` (clock ticks since boot). If `/proc` disappeared
first, the fallback is `boot_id:pid:unknown-<monotonic_ns>` and is visibly
marked. This lets `inspect` distinguish two processes that reused the same PID.

`boot_id` comes from `/proc/sys/kernel/random/boot_id` and is captured once per
session. It changes on reboot, so IDs are not reusable across boots.

## Clocks

Kernel events carry `bpf_ktime_get_ns()`, which is `CLOCK_MONOTONIC` since boot.
At session start the collector captures:

```
wall_offset_ns = CLOCK_REALTIME - CLOCK_MONOTONIC
```

Every event stores both `timestamp_ns` (derived wall clock) and `monotonic_ns`
(raw kernel value). Ordering and correlation should prefer `monotonic_ns`
because a later NTP step can move the derived wall clock. Both are exposed in the
database and JSON output.

## Storage and concurrency

- SQLite is opened in WAL mode with `synchronous=NORMAL`, `foreign_keys=ON`,
  `busy_timeout=5000`, and `trusted_schema=OFF`.
- The session row is inserted before recording starts.
- The ring-buffer callback never performs disk I/O. It uses `try_send` on a
  bounded `sync_channel` of 8192 events; a full channel increments the
  userspace-drop counter.
- A dedicated writer thread owns its own SQLite connection, batches up to 256
  events or 200 ms, and commits each batch in one transaction. If a later batch
  fails, the writer reports the committed count and error separately so partial
  evidence is still accounted for.
- Inspection commands open the database read-only and verify `PRAGMA
  user_version` before querying.
- All SQL values are bound parameters. Event queries support session id, event
  type, pid, limit, and offset, with indexes for session/time, session/type,
  pid, process instance, and timestamp.

## Failure handling

| Failure | Behavior |
| --- | --- |
| No BPF privilege | Explicit `InsufficientPrivilege`, exit 1; no partial session |
| Skeleton open/load/attach failure | Explicit phase error, exit 1 |
| Bad ring-buffer sample | Counted as malformed, discarded, session continues |
| Event filtered by scope | Counted as filtered, session continues |
| Bounded channel full | Counted as userspace dropped, session continues |
| Ring buffer output failure | eBPF counter, read and persisted at session end |
| Writer/SQLite failure | Session marked `failed`, error persisted; already-committed rows remain and are reported |
| Target exits | Drain window of 750 ms, then finalize; detached descendants that outlive the target are not followed |
| Ctrl+C / SIGTERM | Mark interrupted, SIGTERM target group, 2 s grace, SIGKILL if needed, 500 ms drain, exit 130 |
| Recorder panic/unwind | Drop guard marks session `failed` |
| Hard crash | Session remains `recording` but is inspectable read-only |
| PID reuse | Distinct process instance identity; no inherited target-tree trust |
| Missing syscall enter/exit or pairing-map eviction | No activity event emitted; not separately counted (documented gap) |
| Relative path | Raw path persisted with `path_is_absolute=false` and `dirfd`; collector does not resolve |
| IPv4/IPv6 connect | Family/address/port persisted; success only means `connect()` returned 0; source usually unavailable |

## Behavioral analysis

Phase 6 adds an offline analysis subsystem rather than putting rules in the
collector hot path. `syscall-analysis` reads persisted evidence through existing
bounded storage APIs and emits versioned findings whose supporting events are
referenced by original row ID. The shared result model lives in `syscall-core`;
CLI rendering and export assembly remain in `syscall-cli`.

Analysis is read-only: it does not migrate, update, or execute recorded
commands. Event scanning is bounded by `max_events`, findings by `max_findings`,
and per-rule work is bounded (for example, shell traversal and process-tree
correlation caps). Rule F groups events by process instance once rather than
rescanning the full event list per process.

Evidence completeness is explicit. Losses, userspace drops, malformed events,
persistence failures, unresolved identity/ancestry, non-terminal sessions, and
truncated scans reduce confidence and appear in report limitations. Verification
is read-only; analysis does not claim database authenticity.

See [ANALYSIS.md](ANALYSIS.md) for exact rule conditions, severity/confidence
semantics, configuration defaults, CLI examples, and export integration.

## Tradeoffs

- Fixed tracepoint structs are less portable across kernel versions than CO-RE,
  but every field is checked by BTF and static assertions on this target.
- Target-tree filtering in userspace is simpler and more transparent than a
  kernel map, but the kernel still produces system-wide samples that userspace
  may discard.
- One writer thread and one read-only connection per inspection command keep the
  design small. There is no concurrent multi-reader aggregation layer.
- Activity is sampled at syscall exit. This is portable across filesystems and
  protocols but cannot prove data access, TCP/UDP, or connection establishment;
  deeper hooks would add kernel-version and attribution risk.
- Only `openat` and `connect` are captured. `open`, `openat2`, `sendto`,
  `sendmsg`, and `accept` are not part of Phase 5.
- The wall-clock offset is captured once. This favors internal consistency over
  responding to clock steps mid-session.
