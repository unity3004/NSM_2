-- Tracks whether the very first administrator has been created yet — a
-- fresh installation has zero organizations and zero users, so there is
-- no existing row anywhere else in the schema to derive that fact from
-- safely. A singleton table (exactly one row, enforced below) rather than
-- a derived `SELECT EXISTS(SELECT 1 FROM users)` check for two reasons:
-- (1) that derived check has no natural place to take a lock against — see
-- platform_repository.go's use of `SELECT ... FOR UPDATE` on this row to
-- serialize concurrent bootstrap attempts, the same row-locking idea
-- audit_repository.go already uses via pg_advisory_xact_lock for its own
-- hash-chain writes; (2) it survives a future world where users can be
-- deleted back down to zero without the platform becoming "uninitialized"
-- again.
CREATE TYPE platform_bootstrap_status AS ENUM ('uninitialized', 'initializing', 'initialized'); -- entity.PlatformBootstrapStatus

CREATE TABLE platform_bootstrap (
    id              SMALLINT PRIMARY KEY DEFAULT 1,
    status          platform_bootstrap_status NOT NULL DEFAULT 'uninitialized',
    initialized_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    initialized_at  TIMESTAMPTZ,
    CONSTRAINT ck_platform_bootstrap_singleton CHECK (id = 1)
);

-- Backfill for a database this migration runs against that already has
-- real users (any existing deployment upgrading to this version, and —
-- deliberately — this project's own dev/test databases, which already
-- have fixture users from earlier work). Without this, an already-live,
-- already-populated installation would suddenly show as "uninitialized"
-- the moment this migration runs, re-opening the bootstrap endpoint on a
-- system that very much already has administrators. A truly fresh
-- database (no rows in `users` yet) correctly seeds 'uninitialized'.
INSERT INTO platform_bootstrap (id, status)
VALUES (1, (CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'initialized' ELSE 'uninitialized' END)::platform_bootstrap_status);
