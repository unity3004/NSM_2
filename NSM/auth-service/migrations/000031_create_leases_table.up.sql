-- Sprint 5 Task 2: Dynamic Secrets & Secret Leasing.
--
-- A lease is a deliberately separate model from secrets/secret_versions —
-- see internal/service/lease_service.go's own package doc comment for the
-- "static vs dynamic, do not mix these two models unnecessarily" reasoning.
-- A lease never stores the credential it represents: only enough metadata
-- to track its lifecycle (owner, expiry, status, an opaque provider
-- reference such as a generated username) and to prove, later, that it
-- once existed and what happened to it (via audit_logs).

CREATE TYPE lease_status      AS ENUM ('active', 'revoked', 'expired');        -- entity.LeaseStatus
CREATE TYPE lease_owner_type  AS ENUM ('user', 'service_account');             -- entity.LeaseOwnerType

-- lease_type is TEXT, not an enum: it names a DynamicCredentialProvider
-- registered with LeaseService (see that type's own doc comment) —
-- providers are expected to be added over time (a future Postgres,
-- AWS IAM, etc. provider), and a Postgres enum would need a migration for
-- every new one; the provider registry itself is already the source of
-- truth for which values are actually valid at request time.
CREATE TABLE leases (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    lease_type          VARCHAR(100) NOT NULL,
    resource_path       VARCHAR(1040) NOT NULL,
    owner_identity_type lease_owner_type NOT NULL,
    owner_identity_id   UUID NOT NULL,
    status              lease_status NOT NULL DEFAULT 'active',
    renewable           BOOLEAN NOT NULL DEFAULT false,
    -- ttl_seconds is the *effective* TTL currently granted — updated on
    -- every renewal to the new remaining window; max_ttl_seconds is a
    -- fixed ceiling snapshotted from configuration at creation time that
    -- neither this lease's own TTL nor any renewal of it may ever exceed
    -- (see LeaseService.Renew's own doc comment).
    ttl_seconds         INTEGER NOT NULL CHECK (ttl_seconds > 0),
    max_ttl_seconds     INTEGER NOT NULL CHECK (max_ttl_seconds > 0),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      VARCHAR(255),
    -- provider_reference is an opaque, provider-specific handle (e.g. a
    -- generated username) a provider may need to revoke or renew the
    -- underlying credential later — never a password, key, or token; see
    -- this migration's own header comment and DynamicCredentialProvider's
    -- doc comment for why credential material itself never has a column
    -- here at all.
    provider_reference  VARCHAR(255),
    -- metadata is safe, non-sensitive, provider-supplied context (e.g.
    -- {"username": "..."}) — never a password or secret value. Enforced
    -- in Go (entity.Lease / DynamicCredentialProvider's own contract),
    -- not by this column's type, the same trust boundary
    -- audit_logs.metadata already operates under.
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_leases_owner        ON leases (owner_identity_type, owner_identity_id);
CREATE INDEX idx_leases_status       ON leases (status);
CREATE INDEX idx_leases_expires_at   ON leases (expires_at) WHERE status = 'active';
CREATE INDEX idx_leases_resource     ON leases (organization_id, resource_path);

-- Permission catalog: leases is its own resource, separate from secrets:*
-- and from service_accounts:*/api_keys:* — the same deliberate separation
-- secret_policies (000028) established from secrets itself and
-- service_accounts/api_keys (000030) established from each other: a role
-- that can read static secrets must not automatically be able to issue
-- dynamic credentials (this sprint's own explicit "must NOT be able to
-- obtain dynamic credentials merely because it can access static
-- secrets" requirement) — leases:create is the deliberate, additional
-- gate LeaseService.authorizeCreate checks on top of the existing
-- secrets:read + path-policy chain, never a replacement for either.
-- There is no leases:renew — renewal is owner-only by design (see
-- LeaseService.Renew's own doc comment), never an administrative action
-- a separate permission would gate.
INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000140', 'leases', 'create', 'Issue a dynamic secret lease'),
    ('00000000-0000-4000-9000-000000000141', 'leases', 'read',   'View any lease''s metadata (owners can always view their own)'),
    ('00000000-0000-4000-9000-000000000142', 'leases', 'revoke', 'Revoke any lease (owners can always revoke their own)');

-- Platform Administrator gets every new permission — the same rule every
-- prior catalog extension in this codebase already applied.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000001', id FROM permissions
WHERE id IN (
    '00000000-0000-4000-9000-000000000140',
    '00000000-0000-4000-9000-000000000141',
    '00000000-0000-4000-9000-000000000142'
);
