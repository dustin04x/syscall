-- SYSCALL schema version 1.
--
-- Timestamps are nanoseconds. `timestamp_ns` is wall-clock time derived from
-- the kernel monotonic clock plus a captured offset; `monotonic_ns` is the raw
-- bpf_ktime_get_ns() value and is the preferred ordering key for correlation.

CREATE TABLE sessions (
    id                       TEXT PRIMARY KEY NOT NULL,
    schema_version           INTEGER NOT NULL,
    started_at_ns            INTEGER NOT NULL,
    ended_at_ns              INTEGER,
    command                  TEXT NOT NULL,
    arguments                TEXT NOT NULL,
    recording_scope          TEXT NOT NULL,
    status                   TEXT NOT NULL,
    boot_id                  TEXT,
    kernel_release           TEXT,
    collector_version        TEXT,
    dropped_events           INTEGER NOT NULL DEFAULT 0,
    ringbuf_lost_events      INTEGER NOT NULL DEFAULT 0,
    userspace_dropped_events INTEGER NOT NULL DEFAULT 0,
    malformed_events         INTEGER NOT NULL DEFAULT 0,
    filtered_events          INTEGER NOT NULL DEFAULT 0,
    error                    TEXT
);

CREATE TABLE events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    schema_version      INTEGER NOT NULL,
    event_type          TEXT NOT NULL,
    timestamp_ns        INTEGER NOT NULL,
    monotonic_ns        INTEGER NOT NULL,
    pid                 INTEGER NOT NULL,
    tid                 INTEGER NOT NULL,
    ppid                INTEGER,
    uid                 INTEGER NOT NULL,
    gid                 INTEGER NOT NULL,
    process_instance_id TEXT NOT NULL,
    comm                TEXT NOT NULL,
    payload             TEXT NOT NULL
);

CREATE INDEX idx_events_session_id ON events(session_id);
CREATE INDEX idx_events_timestamp ON events(timestamp_ns);
CREATE INDEX idx_events_pid ON events(pid);
CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_session_time ON events(session_id, timestamp_ns, id);
CREATE INDEX idx_events_session_type ON events(session_id, event_type);
CREATE INDEX idx_events_process_instance ON events(process_instance_id);
