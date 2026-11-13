# Event and Storage Schema

There are three independently versioned contracts:

| Contract | Constant | Current value | Enforced by |
| --- | --- | --- | --- |
| Ring-buffer wire format | `SYSCALL_EVENT_VERSION` / `WIRE_SCHEMA_VERSION` | 3 (decoder accepts 1/2 for process lifecycle; file/network require 3) | eBPF layout/static checks, Rust decoder magic/version/size checks |
| Domain event schema | `SCHEMA_VERSION` | 2 (readable: 1–2) | `Event::validate`, JSON payloads, storage rows |
| SQLite schema | `PRAGMA user_version` | 5 | `syscall-storage` migrations |

A database with a newer SQLite schema, an event with a schema newer than this
build, or a ring sample with a different wire schema is rejected explicitly
rather than interpreted optimistically. Domain v1 events remain readable; their
`tid` retains the v1 meaning (process TGID).

## Ring-buffer wire format

All multi-byte fields are native-endian; producer and consumer are the same host.
The structures are 8-byte aligned. Strings are NUL-terminated within their fixed
buffers unless otherwise noted.

### Header (`struct syscall_event_hdr`, 56 bytes)

| Offset | Size | Type | Field | Meaning |
| ---: | ---: | --- | --- | --- |
| 0 | 4 | `u32` | `magic` | `0x5343594c` (`"SYCL"` native u32) |
| 4 | 2 | `u16` | `schema_version` | Wire version (current 3; decoder accepts 1/2 only for process lifecycle samples) |
| 6 | 2 | `u16` | `event_type` | 1 exec, 2 fork, 3 exit, 4 file-open, 5 network-connect |
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

### File-open sample (`struct syscall_event_file_open`, 336 bytes)

Emitted at `syscalls/sys_exit_openat` after a matching `syscalls/sys_enter_openat`.

| Offset | Size | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 56 | header | `hdr` |
| 56 | 8 | `s64` | `result` |
| 64 | 4 | `s32` | `dirfd` |
| 68 | 4 | `u32` | `flags` |
| 72 | 1 | `u8` | `path_is_absolute` |
| 73 | 1 | `u8` | `path_truncated` |
| 74 | 6 | `u8[6]` | `_pad` |
| 80 | 256 | `char[256]` | `path` |

`result` is the raw syscall return: a non-negative file descriptor on success
or a negative errno on failure. `path` is the string supplied to `openat(2)`,
not a resolved absolute path. `dirfd == -100` (`AT_FDCWD`) means the process
current directory; other values identify the directory descriptor. The decoder
requires `data_len <= 256`, NUL termination, and rejects samples shorter than
336 bytes. `path_truncated` is set when the kernel string exceeded the capture
buffer; the saved string is still NUL-terminated.

### Network-connect sample (`struct syscall_event_network_connect`, 104 bytes)

Emitted at `syscalls/sys_exit_connect` after a matching
`syscalls/sys_enter_connect`, only for `AF_INET`/`AF_INET6` destinations.

| Offset | Size | Type | Field |
| ---: | ---: | --- | --- |
| 0 | 56 | header | `hdr` |
| 56 | 8 | `s64` | `result` |
| 64 | 2 | `u16` | `family` (`AF_INET`=2, `AF_INET6`=10) |
| 66 | 2 | `u16` | `destination_port` (network byte order) |
| 68 | 2 | `u16` | `source_port` (network byte order) |
| 70 | 1 | `u8` | `address_len` |
| 71 | 1 | `u8` | `source_available` |
| 72 | 16 | `u8[16]` | `destination_address` |
| 88 | 16 | `u8[16]` | `source_address` |

IPv4 addresses occupy the first four bytes and are zero-padded. The decoder
validates the declared family, address length (4 or 16), and that address bytes
after the valid length are zero. Ports are converted from network byte order.
`source_available == 0` means the source address/port were not exposed by the
hook and are stored as `null`, not guessed.

## Domain event

```json
{
  "id": 42,
  "session_id": "s-1762632000000-0123456789abcdef",
  "schema_version": 2,
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

For schema v2, `tid` preserves the kernel-observed thread ID for `file_open` and
`network_connect` events. For process lifecycle events it remains the process
TGID. Schema v1 rows stored the process TGID in `tid` for every event, so
consumers must use `schema_version` when interpreting historical rows.

### Payload variants

All five collected variants are persisted; the previous `file_open` and
`network_connect` placeholders were replaced with real payloads. Domain
`schema_version` is `2`; the wire format carries the activity semantics.

| `kind` | Fields |
| --- | --- |
| `process_exec` | `filename`, `ppid`, `start_time_ticks`, `old_pid` |
| `process_fork` | `parent_pid`, `parent_tgid`, `child_pid`, `child_comm`, `child_start_time_ticks` |
| `process_exit` | `ppid`, `start_time_ticks`, `exit_priority` |
| `file_open` | `path`, `path_is_absolute`, `path_truncated`, `dirfd`, `flags`, `result`, `success`, `errno` |
| `network_connect` | `family` (`ipv4`/`ipv6`), `source_address`, `source_port`, `destination_address`, `destination_port`, `result`, `success`, `errno`, `established` |

`file_open.success` is `result >= 0`; `network_connect.success` is `result == 0`.
For failed events `errno` is `-result` when representable, and `null` otherwise.
`network_connect.established` is always `false`: the syscall hook proves a
connect attempt, not an established connection, and cannot distinguish TCP from
UDP.

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
- File paths longer than 256 bytes or containing NUL.
- Invalid address family, address-length mismatch, or unparseable addresses.
- Activity `success`/`errno` inconsistent with the raw result.
- A network event claiming `established = true`.
- Negative `ppid` or `old_pid`.
- Oversized fork comm fields.

Storage validates the whole batch before opening the transaction, and again
checks that every event's `session_id` matches the batch session.

## SQLite schema version 5

Versions 2–5 are additive: v2 adds provenance columns, v3 adds recovery/accounting
fields and event ordering support, v4 adds activity-query indexes, and v5 adds
the collector self-filter counter. Existing sessions remain readable and no
historical rows are rewritten.

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
| `events_received` | INTEGER | Ring samples received |
| `events_decoded` | INTEGER | Samples decoded successfully |
| `events_attributed` | INTEGER | Decoded samples attributed to the recording |
| `events_persisted` | INTEGER | Committed event rows (authoritative count) |
| `events_rejected_scope` | INTEGER | Scope rejections |
| `events_rejected_malformed` | INTEGER | Decode/malformed rejections |
| `events_persist_failed` | INTEGER | Persistence failure indicator |
| `events_self_filtered` | INTEGER | Collector-generated samples discarded before attribution (v5) |
| `error` | TEXT NULL | Finalization/writer error |

### `events`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PK AUTOINCREMENT | Query/order id |
| `session_id` | TEXT FK | `ON DELETE CASCADE` |
| `schema_version` | INTEGER | Domain schema version |
| `event_type` | TEXT | `process_exec`, `process_fork`, `process_exit`, `file_open`, `network_connect` |
| `timestamp_ns` | INTEGER | Derived wall clock |
| `monotonic_ns` | INTEGER | Raw kernel timestamp |
| `pid` | INTEGER | Process/task id |
| `tid` | INTEGER | Observed thread ID for v2 activity events; process TGID for lifecycle events and all v1 rows |
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
idx_events_session_type_time (session_id, event_type, timestamp_ns, id)   -- v4
idx_events_session_instance_time (session_id, process_instance_id, timestamp_ns, id) -- v4
```

Activity queries use SQL `json_valid`/`json_extract` on `payload` for
`$.success` and `$.family`, combined with the v4 indexes, and always order by
`timestamp_ns ASC, monotonic_ns ASC, id ASC`.

### Migration policy

Migrations are ordered by `PRAGMA user_version`. A writable open applies all
pending migrations in a transaction and bumps `user_version`. A read-only open
never migrates: it rejects version 0 (missing schema) and any version newer than
the binary supports. A schema bump requires a new migration file and an update to
`LATEST_SCHEMA_VERSION`; existing databases are never rewritten in place without
a transaction.
