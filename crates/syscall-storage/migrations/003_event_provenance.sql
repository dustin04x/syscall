-- Phase 2 (Mission 02): event provenance, identity evidence, and deterministic ordering metadata.
-- Additive/backwards-compatible: historical rows keep NULLs/unknowns (never fabricated).

ALTER TABLE events ADD COLUMN raw_bpf_pid INTEGER;
ALTER TABLE events ADD COLUMN raw_bpf_tgid INTEGER;
ALTER TABLE events ADD COLUMN observer_pid INTEGER;
ALTER TABLE events ADD COLUMN observer_tgid INTEGER;
ALTER TABLE events ADD COLUMN source_tracepoint TEXT;
ALTER TABLE events ADD COLUMN wire_schema_version INTEGER;
ALTER TABLE events ADD COLUMN attribution_method TEXT;
ALTER TABLE events ADD COLUMN timestamp_clock_domain TEXT;
ALTER TABLE events ADD COLUMN monotonic_clock_domain TEXT;
