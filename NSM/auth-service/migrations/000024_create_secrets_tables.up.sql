-- Sprint 3 Phase 1 — the database foundation for the Secrets Engine.
-- Deliberately schema-only: no encryption is implemented yet (see
-- internal/secrets, a later phase), so ciphertext/nonce/auth_tag/wrapped_dek
-- below are opaque BYTEA columns this migration never writes to — nothing
-- in this migration or the repository layer built on it can produce or
-- interpret their contents.
--
-- secrets is the stable logical identity (one row per path, forever);
-- secret_versions is the append-only history of encrypted payloads for
-- that identity. This mirrors the existing users/user_roles split: a
-- stable parent identity, with a separate table for the append-only,
-- never-overwritten facts about it (login_history and audit_logs are the
-- other examples of that same append-only shape in this schema).

-- citext (already enabled by 000001) gives path the same case-insensitive
-- uniqueness users.email already relies on — Prod/Database and
-- prod/database must be the same secret, not two.
CREATE TABLE secrets (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    path              CITEXT NOT NULL,
    current_version   INT NOT NULL DEFAULT 0,
    created_by        UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ,
    CONSTRAINT uq_secrets_org_path UNIQUE (organization_id, path),
    CONSTRAINT ck_secrets_current_version_nonneg CHECK (current_version >= 0),
    -- Path validation lives at the DTO layer for the same reason
    -- RegisterRequest.Validate() (not a CHECK constraint) enforces email
    -- shape — richer error messages than a constraint violation can give,
    -- and no round trip to discover which rule failed. This CHECK is the
    -- one rule cheap and unconditionally safe enough to enforce at the
    -- database layer too, defense-in-depth against any future write path
    -- that skips DTO validation: never empty, never longer than the
    -- column's own 1024-byte budget.
    CONSTRAINT ck_secrets_path_not_empty CHECK (length(path::text) > 0 AND length(path::text) <= 1024)
);

CREATE INDEX idx_secrets_organization_id ON secrets (organization_id);
-- Partial: every "list/lookup active secrets" query filters out deleted
-- rows (see secrets.deleted_at); a full index would carry entries this
-- codebase's own query pattern never asks for. Mirrors
-- idx_users_status's identical "WHERE deleted_at IS NULL" partial-index
-- convention.
CREATE INDEX idx_secrets_active ON secrets (organization_id, path) WHERE deleted_at IS NULL;

CREATE TABLE secret_versions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id      UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version        INT NOT NULL,
    ciphertext     BYTEA NOT NULL,
    nonce          BYTEA NOT NULL,
    auth_tag       BYTEA NOT NULL,
    algorithm      VARCHAR(50) NOT NULL,
    wrapped_dek    BYTEA NOT NULL,
    key_id         VARCHAR(255) NOT NULL,
    key_version    VARCHAR(50),
    created_by     UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ,
    -- The hard backstop the objective requires: "the database must
    -- prevent duplicate versions," not just the application. Two
    -- concurrent writers both attempting to insert (secret_id, 3) can
    -- only ever have one succeed — Postgres's own unique-index enforcement,
    -- not a race the Go code has to detect and resolve itself. See
    -- secret_repository.go's CreateVersion for how the service layer
    -- turns the resulting 23505 into entity.ErrAlreadyExists, the same
    -- translateError path uq_secrets_org_path and every other unique
    -- constraint in this schema already goes through.
    CONSTRAINT uq_secret_versions_secret_version UNIQUE (secret_id, version),
    CONSTRAINT ck_secret_versions_version_positive CHECK (version > 0)
);

-- (secret_id, version DESC) serves both real query shapes this table
-- has: "get the current version" (version = secrets.current_version,
-- looked up by secret_id) and "list this secret's history, newest
-- first" — one composite index, not two, since the leading column
-- (secret_id) already makes it useful for a bare secret_id lookup too.
CREATE INDEX idx_secret_versions_secret_id ON secret_versions (secret_id, version DESC);
