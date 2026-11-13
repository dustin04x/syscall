# Security and Threat Model

## Scope

SYSCALL is a local forensic recorder. It assumes a trusted operator who may run
a privileged command explicitly and an untrusted set of observed processes. It
does **not** defend against a malicious root user, a compromised kernel, or a
host that is already under privileged attack.

## Privilege model

Loading and attaching eBPF requires `CAP_BPF` + `CAP_PERFMON` (Linux 5.8+),
`CAP_SYS_ADMIN`, or effective UID 0. SYSCALL never calls `sudo`, never asks for a
password, and never stores credentials.

Recommended invocation:

```bash
sudo /absolute/path/to/syscall record --db /home/alice/.local/share/syscall/syscall.db -- /usr/bin/sleep 5
```

When started through sudo:

1. The process loads/attaches the BPF programs as root.
2. It reads `SUDO_UID`/`SUDO_GID`, calls `setgroups(0)`, `setgid`, and `setuid`.
3. It verifies `geteuid`/`getegid` actually changed.
4. It sets `umask 077`.
5. Only then does it create the database and spawn the target.

Consequences:

- The target command and database are owned by the invoking user, not root.
- `syscall inspect`/`sessions`/`events` work later without root.
- If SYSCALL is launched from a **root shell** (no `SUDO_UID`), it stays root and
  the target runs as root. That is an explicit operator choice and should be
  avoided unless intended.
- If `SUDO_UID=0`, the privilege drop is skipped and the target runs as root.

The collector does not attempt to regain privilege after the drop.

## Data handling

Collected data now includes process lifecycle, file-open, and IP connect
metadata:

- Command name (`comm`), executable filename for exec, PID/TID/PPID, UID/GID.
- Raw `openat(2)` path strings, flags, dirfd, and raw result. Paths may reveal
  sensitive filenames or directory structure.
- Connect address family, destination/source IP and port, and raw result. This
  metadata reveals destinations but not payloads.
- Timestamps and a stable process-instance identity.
- No file contents, environment variables, memory, packet payloads, DNS names,
  or command-line arguments are read from the kernel.

Target arguments are stored in the session row by default because they are
forensically useful. They can contain secrets. Use:

```bash
sudo syscall record --redact-args -- some-command --token=secret
```

This replaces all arguments with `"<redacted>"`; the command path is still
stored. Arguments are JSON-encoded in SQLite and escaped in all output.

## Storage protections

- Default data directory: `~/.local/share/syscall` (the invoking user's home
  when launched through sudo).
- Data directory mode: `0700`.
- Database file mode: `0600`.
- `umask 077` is set before database creation and target spawn, so SQLite WAL
  and SHM sidecars are private.
- SQLite settings: WAL, `synchronous=NORMAL`, `foreign_keys=ON`,
  `busy_timeout=5000`, `trusted_schema=OFF`.
- Inspection opens read-only and verifies `PRAGMA user_version`.
- All SQL values are bound parameters. No user value is interpolated into SQL
  text.
- Schema migrations run in transactions and reject newer versions.

The database path is operator-controlled. A user who can replace it can only
affect their own process, because writes happen after the privilege drop.

## Memory and denial-of-service bounds

- eBPF uses a 4 MiB ring buffer and fixed-size stack events.
- The userspace channel is bounded at 8192 events.
- The writer batches at most 256 events per transaction.
- Filename/path capture is bounded at 256 bytes; comm is 16 bytes.
- Syscall pairing maps are bounded LRU hashes of 8192 entries each; eviction or a
  missing enter means the attempt is not reported, never invented.
- Activity events are fixed-size wire structs; file-open events are
  ring-buffer-reserved to avoid exceeding the BPF stack.
- Malformed samples are discarded and counted; they cannot panic the decoder.
- Out-of-scope and dropped events are counted separately, so a busy host does
  not silently look complete.
- `/proc` ancestry walks are capped at 64 levels.
- The tracked-process table is capped at 65,536 live instances; excess new
  processes are filtered and counted rather than growing memory without bound.

A sufficiently busy host can still lose events. The loss counters are persisted
and shown by `inspect`; a session with drops is not presented as complete.

## Input validation

The kernel is treated as untrusted input even though the programs are ours:

- Magic, schema, type, length, bounds, and NUL termination are checked.
- Pid/tgid must be positive; timestamps must be sane.
- Strings are decoded lossily but bounded.
- Domain events are validated before any SQL transaction.
- Event type and payload variant must agree.
- Schema-only event types cannot be persisted.

## Terminal and output safety

Process names, filenames, command arguments, and stored error strings may contain
control characters. Text output escapes control characters before truncation, so
kernel data cannot inject ANSI escape sequences. JSON output relies on Serde's
standard string escaping. Timestamps are always rendered as UTC.

## Argument and path handling

- Target arguments are passed as `OsString` values without shell evaluation.
- `syscall record -- command args...` requires the `--` separator, so target
  flags cannot be mistaken for recorder flags.
- The target is spawned in its own process group; Ctrl+C is handled by the
  collector, which then signals the group with SIGTERM and, after a grace period,
  SIGKILL.
- Error messages that include target paths use debug formatting, which escapes
  control characters.

## Failure and crash behavior

- A failed writer marks the session `failed` and records the error.
- An unwind triggers a `Drop` guard that attempts to finalize the session.
- A hard crash leaves the row in `recording`; data already committed remains
  readable. Operators must treat a `recording` row as incomplete.
- Signals are handled with an async-signal-safe atomic store; no allocation or
  locks occur in the handler.

## Known security limitations

- Target-tree scope is not a security boundary. The kernel observes system-wide
  events and userspace filters them; a hostile process that can forge ancestry
  timing races may influence attribution, but cannot inject events.
- `/proc` reads can race with process exit. Missing metadata falls back to cached
  values and is marked where possible.
- Thread-vs-process discrimination is best-effort when the child disappears
  before `/proc/<pid>/status` can be read.
- The wall-clock offset is captured once; clock changes can skew derived wall
  timestamps, though monotonic timestamps remain ordered.
- File paths are recorded exactly as passed to `openat`, not resolved. Relative
  paths and `dirfd` bases require investigator interpretation; a path alone does
  not prove which file was ultimately accessed.
- A file-open event proves the syscall attempt and return value, not that file
  contents were read or written.
- Connect events prove `connect(2)` attempts, not established connections,
  payload transfer, or application protocol. The syscall tracepoint cannot
  distinguish TCP from UDP, and source addresses are usually unavailable.
- Missing syscall enter/exit samples or pairing-map evictions are not separately
  counted; absent activity is not proof of no activity.
- There is no integrity signature or tamper-evident log. An attacker with write
  access to the database can modify it.
- No audit log records who ran the privileged recorder; use your OS audit
  tooling for that.


## Investigation and evidence export (Phase 4)

Investigation commands (`processes`, `tree`, `timeline`, `stats`, `export`) operate on persisted evidence only:

- **Read-only access:** session inspection/verification/export open databases read-only (`query_only`) and do not run migrations or modify recording data. Export never modifies the original recording database.
- **No execution:** recorded commands/event payloads are treated as untrusted data and are never executed.
- **Redaction preserved:** session arguments are reported/exported as recorded. If `--redact-args` was used, original argument values are not present and are not revealed by investigation/export.
- **No secrets/unrelated data:** environment variables are never exported. Only the requested session is exported; unrelated sessions are excluded.
- **Output safety:** human-readable terminal output escapes control characters in untrusted fields to prevent escape-sequence injection. JSON output remains valid for unusual characters.
- **Export file handling:** JSON export is written atomically (temporary file in the destination directory, fsync, rename) with restrictive permissions (`0600` on Unix). An existing output file is never overwritten without an explicit `--force` flag. The destination directory must already exist.
- **Integrity manifest:** exports include SHA-256 digests over exported evidence components for post-export integrity checking. `syscall verify-export` checks these hashes and byte lengths read-only; it does not prove the original database was authentic or untampered before export and is not a digital signature or chain of custody.
- **Honest incompleteness:** when kernel/userspace losses occurred, identity/ancestry is unresolved, provenance is unavailable (legacy records), or verification cannot complete, outputs/exports state limitations explicitly rather than implying complete or valid evidence.
