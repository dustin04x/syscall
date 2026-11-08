# Event and Storage Schema

There are three independently versioned contracts:

| Contract | Constant | Current value | Enforced by |
| --- | --- | --- | --- |
| Ring-buffer wire format | `SYSCALL_EVENT_VERSION` / `WIRE_SCHEMA_VERSION` | 2 (decoder accepts 1/2) | eBPF layout/static checks, Rust decoder magic/version/size checks |
| Domain event schema | `SCHEMA_VERSION` | 1 | `Event::validate`, JSON payloads, storage rows |
| SQLite schema | `PRAGMA user_version` | 1 | `syscall-storage` migrations |

A database with a newer SQLite schema, an event with a different domain schema,
or a ring sample with a different wire schema is rejected explicitly rather than
interpreted optimistically.

## Ring-buffer wire format

All multi-byte fields are native-endian; producer and consumer are the same host.
The structures are 8-byte aligned. Strings are NUL-terminated within their fixed
buffers unless otherwise noted.

### Header (`struct syscall_event_hdr`, 56 bytes)

| Offset | Size | Type | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 4 | `u32` | `magic` | `0x5343594c` (`"SYCL"` native u32) |
| 4 | 2 | `u16` | `schema_version` | Wire version (current 2; decoder accepts 1/2 for compatibility) |
| 6 | 2 | `u16` | `event_type` | 1 exec, 2 fork, 3 exit |
| 8 | 8 | `u64` | `timestamp_ns` | Raw `bpf_ktime_get_ns()` (CLOCK_MONOTONIC ns) |
| 16 | 4 | `u32` | `pid` | Task id (kernel/BPF context) |
| 20 | 4 | `u32` | `tgid` | Thread group id (kernel/BPF context) |
| 24 | 4 | `u32` | `uid` | Current uid from `bpf_get_current_uid_gid` |
| 28 | 4 | `u32` | `gid` | Current gid from `bpf_get_current_uid_gid` |
| 32 | 16 | `char[16]` | `comm` | `TASK_COMM_LEN`, NUL-terminated/truncated |
| 48 | 4 | `u32` | `data_len` | Payload length in bytes (excludes trailing NUL where applicable) |
| 52 | 4 | `u32`/`i32` | `ns_tgid` | Observer/collector PID-namespace TGID when known; `0` if unavailable. Wire v1 treated this as reserved/zero. |

`magic` is written as a native `u32`, so the on-disk byte order is the host's
byte order. The decoder rejects magic/version mismatches and performs strict bounds/NUL checks.

### Exec sample (`struct syscall_event_exec`, 320 bytes)

| Offset | Size | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 56 | header | `hdr` |
| 56 | 4 | `s32` | `old_pid` |
| 60 | 256 | `char[256]` | `filename` |

`hdr.data_len` is the filename length excluding the NUL. The decoder requires
`data_len <= 256`, requires the byte at `60 + data_len` to be NUL when
`data_len > 0`, and rejects samples shorter than 320 bytes.

### Fork sample (`struct syscall_event_fork`, 96 bytes)

| Offset | Size | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 56 | header | `hdr` |
| 56 | 4 | `u32` | `parent_pid` |
| 60 | 4 | `u32` | `child_pid` |
| 64 | 16 | `char[16]` | `parent_comm` |
| 80 | 16 | `char[16]` | `child_comm` |

The header's `pid` and `tgid` are both set to `child_pid` because the tracepoint
provides task PIDs. Userspace checks `/proc/<child>/status` to reject
thread-creation events when the child is not a process leader.

### Exit sample (`struct syscall_event_exit`, 64 bytes)

| Offset | Size | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 56 | header | `hdr` |
| 56 | 4 | `s32` | `exit_priority` (`ctx->prio`) |

The exit tracepoint context is
`trace_event_raw_sched_process_template` (32 bytes). The emitted event is 64
bytes because the header is aligned to 8 bytes.

## Domain event

```json
{
  "id": 42,
  "session_id": "s-1762632000000-0123456789abcdef",
  "schema_version": 1,
  "event_type": "process_exec",
  "timestamp_ns": 1762632001000000000,
  "monotonic_ns": 123456789,
  "pid": 4242,
  "tid": 4242,
  "uid": 1000,
  "gid": 1000,
  "ppid": 1,
  "comm": "sleep",
  "process_instance_id": "3f2a...:4242:987654",
  "payload": {
    "kind": "process_exec",
    "filename": "/usr/bin/sleep",
    "ppid": 1,
    "start_time_ticks": 987654,
    "old_pid": 4200
  }
}
```

`id` is assigned by SQLite; it is `null` before persistence.

### Payload variants

Only the first three can be produced or persisted in Mission 01.

| `kind` | Fields |
| --- | --- |
| `process_exec` | `filename`, `ppid`, `start_time_ticks`, `old_pid` |
| `process_fork` | `parent_pid`, `parent_tgid`, `child_pid`, `child_comm`, `child_start_time_ticks` |
| `process_exit` | `ppid`, `start_time_ticks`, `exit_priority` |
| `file_open` | `path` (schema placeholder, rejected by validation) |
| `network_connect` | `family`, `address`, `port` (schema placeholder, rejected by validation) |

The `ppid` and `start_time_ticks` fields are flattened into the payload JSON for
exec and exit because `ProcessMetadata` is a `#[serde(flatten)]` field.

### Validation rules

`Event::validate` rejects:

- Unknown domain schema version.
- Empty/oversized session id, process instance id, comm, or filename.
- Control characters in session or process-instance ids.
- NUL bytes or non-positive pid/tid.
- Non-positive timestamps, wall clock <= 0, monotonic == 0.
- Event type/payload mismatch.
- `file_open` and `network_connect` payloads (no Mission 01 collector).
- Negative `ppid` or `old_pid`.
- Oversized fork comm fields.

Storage validates the whole batch before opening the transaction, and again
checks that every event's `session_id` matches the batch session.

## SQLite schema version 1

### `sessions`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | TEXT PK | Session id |
| `schema_version` | INTEGER | Domain schema version |
| `started_at_ns` | INTEGER | Wall clock, ns since Unix epoch |
| `ended_at_ns` | INTEGER NULL | Wall clock, ns since Unix epoch |
| `command` | TEXT | Program path |
| `arguments` | TEXT | JSON array; may contain `"<redacted>"` |
| `recording_scope` | TEXT | `target-tree` or `system` |
| `status` | TEXT | `starting`, `recording`, `completed`, `interrupted`, `failed` |
| `boot_id` | TEXT NULL | `/proc/sys/kernel/random/boot_id` |
| `kernel_release` | TEXT NULL | `/proc/sys/kernel/osrelease` |
| `collector_version` | TEXT NULL | Crate version |
| `dropped_events` | INTEGER | Ring-buffer lost + userspace dropped |
| `ringbuf_lost_events` | INTEGER | eBPF output failures |
| `userspace_dropped_events` | INTEGER | Bounded-channel drops |
| `malformed_events` | INTEGER | Decoder rejects |
| `filtered_events` | INTEGER | Out-of-scope events |
| `error` | TEXT NULL | Finalization/writer error |

### `events`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Query/order id |
| `session_id` | TEXT FK | `ON DELETE CASCADE` |
| `schema_version` | INTEGER | Domain schema version |
| `event_type` | TEXT | `process_exec`, `process_fork`, `process_exit` |
| `timestamp_ns` | INTEGER | Derived wall clock |
| `monotonic_ns` | INTEGER | Raw kernel timestamp |
| `pid` | INTEGER | Process/task id |
| `tid` | INTEGER | Thread id |
| `ppid` | INTEGER NULL | Parent pid |
| `uid` | INTEGER | User id |
| `gid` | INTEGER | Group id |
| `process_instance_id` | TEXT | PID-reuse-safe identity |
| `comm` | TEXT | Command name |
| `payload` | TEXT | JSON event payload |

Indexes:

```sql
idx_events_session_id        (session_id)
idx_events_timestamp         (timestamp_ns)
idx_events_pid               (pid)
idx_events_event_type        (event_type)
idx_events_session_time      (session_id, timestamp_ns, id)
idx_events_session_type      (session_id, event_type)
idx_events_process_instance  (process_instance_id)
```

### Migration policy

Migrations are ordered by `PRAGMA user_version`. A writable open applies all
pending migrations in a transaction and bumps `user_version`. A read-only open
never migrates: it rejects version 0 (missing schema) and any version newer than
the binary supports. A schema bump requires a new migration file and an update to
`LATEST_SCHEMA_VERSION`; existing databases are never rewritten in place without
a transaction.
