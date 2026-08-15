-- Sprint 4 Task 1 — the durable half of internal/secrets.KeyManager's
-- bookkeeping: which key identifiers this deployment knows about, and
-- each one's lifecycle state (see internal/secrets/key_manager.go's
-- KeyState doc comments for exactly what each state permits). This table
-- stores none of the fields secret_versions already stores
-- (ciphertext/nonce/auth_tag/wrapped_dek) and, like every other table in
-- this schema that touches the Secrets Engine, never stores key material
-- itself — only metadata safe to read in a support ticket.
--
-- Platform-wide, not per-organization: internal/secrets.KeyProvider is
-- constructed once per process (cmd/server/main.go), not once per tenant,
-- so there is no organization_id column here — unlike secrets/secret_versions,
-- which are.

CREATE TYPE key_state AS ENUM ('active', 'retiring', 'retired', 'disabled');

CREATE TABLE encryption_keys (
    key_id       VARCHAR(255) PRIMARY KEY,
    algorithm    VARCHAR(50) NOT NULL,
    state        key_state NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at   TIMESTAMPTZ,
    disabled_at  TIMESTAMPTZ,
    CONSTRAINT ck_encryption_keys_key_id_not_empty CHECK (length(key_id) > 0)
);

-- The invariant internal/secrets.KeyManager's rotation logic depends on —
-- "at most one ACTIVE key at a time" — enforced by the database itself,
-- not only by KeyManager.Rotate's own transaction. A unique index on a
-- column filtered to a single constant value is the standard Postgres
-- idiom for "at most one row may have this value": every row the partial
-- index actually indexes has state = 'active', so a second one would
-- collide.
CREATE UNIQUE INDEX uq_encryption_keys_one_active ON encryption_keys (state) WHERE state = 'active';
