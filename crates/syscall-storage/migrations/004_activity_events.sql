-- Phase 5: filesystem and network activity event indexes.
--
-- Purely additive. Event types are stored in the existing events table; these
-- indexes bound and order activity queries without changing event semantics or
-- rewriting historical rows.

CREATE INDEX IF NOT EXISTS idx_events_session_type_time
    ON events(session_id, event_type, timestamp_ns, id);

CREATE INDEX IF NOT EXISTS idx_events_session_instance_time
    ON events(session_id, process_instance_id, timestamp_ns, id);
