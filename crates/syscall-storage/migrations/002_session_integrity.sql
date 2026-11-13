-- SYSCALL schema version 2: session lifecycle, recovery, and forensic accounting.
-- All additions are backwards-compatible with v1 rows (defaults preserve evidence).

ALTER TABLE sessions ADD COLUMN termination_reason TEXT;
ALTER TABLE sessions ADD COLUMN target_exit_code INTEGER;
ALTER TABLE sessions ADD COLUMN target_exit_signal INTEGER;
ALTER TABLE sessions ADD COLUMN recovered_from_status TEXT;
ALTER TABLE sessions ADD COLUMN recovered_at_ns INTEGER;
ALTER TABLE sessions ADD COLUMN finalized_at_ns INTEGER;

-- Forensic accounting. Existing columns (dropped_events, ringbuf_lost_events,
-- userspace_dropped_events, malformed_events, filtered_events) remain for v1
-- compatibility and are kept consistent with v2 fields.
ALTER TABLE sessions ADD COLUMN events_received INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN events_decoded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN events_attributed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN events_persisted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN events_rejected_scope INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN events_rejected_malformed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN events_persist_failed INTEGER NOT NULL DEFAULT 0;

-- Keep recovered historical rows inspectable: no destructive changes.
-- Recovery is performed by application logic on writable open.
