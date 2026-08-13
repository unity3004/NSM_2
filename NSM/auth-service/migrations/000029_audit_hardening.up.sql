-- Sprint 4 Task 3 — audit & security observability hardening. Extends the
-- existing audit_logs table (migration 000018) rather than creating a
-- second audit mechanism: one new nullable column, two new indexes, and
-- one trigger enforcing at the database level what the application layer
-- already never does (mutate or delete a row).

-- request_id correlates one audit_logs row with the HTTP request that
-- produced it — the same value middleware.RequestID minted or trusted for
-- that request (see internal/util/request_context.go), echoed in the
-- response's X-Request-Id header and in every application log line for
-- the same request. Nullable and added with no backfill: historical rows
-- were written before this column existed and never had a request ID to
-- record — NULL is the honest value for "unknown," not an empty string
-- pretending to be one. Existing rows are otherwise untouched; this is a
-- pure additive column, nothing is rewritten or deleted.
ALTER TABLE audit_logs ADD COLUMN request_id VARCHAR(64);

-- action ("event type" in the objective's own language) is the single
-- highest-value filter an admin reconstructing an incident actually
-- reaches for first ("show me every secret.access_denied", "every
-- policy.deleted") — AuditLogFilter already exposes ActorType/ActorID/
-- ResourceType/ResourceID/Result as filters but had no way to filter by
-- action at all until this task added repository.AuditLogFilter.Action.
CREATE INDEX idx_audit_logs_action ON audit_logs (action);

-- Partial: the large majority of historical rows (everything written
-- before this task) have request_id IS NULL, and "find every row with no
-- request ID" is never a query this system needs to answer quickly — a
-- full index over mostly-NULL values would cost write throughput and
-- storage for no read benefit. WHERE request_id IS NOT NULL keeps the
-- index small and fast for its actual purpose: "given one request ID,
-- find every event it produced" (request correlation, cheap and precise).
CREATE INDEX idx_audit_logs_request_id ON audit_logs (request_id) WHERE request_id IS NOT NULL;

-- No standalone index on `result` alone: it has exactly three values
-- (success/failure/denied — see audit_result's own CREATE TYPE), and a
-- low-cardinality column gains little from its own btree index at any
-- realistic table size — a `result` filter is always combined in practice
-- with organization_id/occurred_at (already indexed via
-- idx_audit_logs_org_occurred) or with action (now indexed above), either
-- of which the planner will already prefer. Adding one anyway would be
-- exactly the "unnecessary index" this task's own instructions warn
-- against.

-- --- Application-level immutability, enforced at the database level ---
--
-- repository.AuditLogRepository has never exposed an Update or Delete
-- method (see that interface's own doc comment) — no code path through
-- this application can currently mutate or remove a row. But "the
-- application's Go code never does it" is not the same guarantee as "the
-- database will refuse to let it happen": the same Postgres role the app
-- connects as has full DML rights on every table it uses, including this
-- one, so a bug elsewhere (a future migration, an operator running ad hoc
-- SQL, a compromised connection string reused somewhere it shouldn't be)
-- could still UPDATE or DELETE a row with nothing to stop it today.
--
-- This trigger closes that gap the same way a hash chain closes the
-- "detect tampering after the fact" gap (migration 000018 already has
-- that): reject the mutation outright, at the database, regardless of
-- which role or code path attempts it. It is deliberately the simplest
-- construct that provides this guarantee — a single BEFORE trigger that
-- raises an exception — not row-level security, not a separate WORM
-- storage engine, not a second copy of the table: see this task's own
-- final report for why true database-level immutability (a dedicated
-- read-only replica role, external WORM/object-lock storage, a
-- restricted grants model separating the app's own DB role from a
-- migration-only superuser) is documented as future work rather than
-- built now. A superuser (or anyone who can DROP TRIGGER) can still
-- disable this — that is the practical, stated limit of what an
-- application-level control can promise, not a claim of absolute
-- tamper-proofing.
CREATE OR REPLACE FUNCTION reject_audit_log_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs rows are immutable: % is not permitted (attempted on id=%)',
        TG_OP, COALESCE(OLD.id, NULL)
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION reject_audit_log_mutation();
