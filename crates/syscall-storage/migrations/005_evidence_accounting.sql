-- Evidence accounting and thread-context metadata.
--
-- `events_self_filtered` accounts for collector-generated activity that is
-- discarded before scope attribution. It is separate from scope/thread
-- filtering so the counters can be reconciled without changing existing
-- evidence semantics. Historical rows receive zero, which is honest for
-- recordings made before this counter existed.

ALTER TABLE sessions ADD COLUMN events_self_filtered INTEGER NOT NULL DEFAULT 0;
