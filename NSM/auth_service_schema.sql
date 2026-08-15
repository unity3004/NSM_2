-- ============================================================================
-- Enterprise Authentication Service — Database Schema
-- Dialect: PostgreSQL 15+
-- Normal form: 3NF (see auth-service-database-schema.md for justification)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;   -- case-insensitive email column

-- ----------------------------------------------------------------------------
-- ENUM TYPES
-- ----------------------------------------------------------------------------

CREATE TYPE org_status              AS ENUM ('active', 'suspended', 'deleted');
CREATE TYPE user_status             AS ENUM ('active', 'disabled', 'locked', 'pending_verification');
CREATE TYPE service_account_status  AS ENUM ('active', 'disabled');
CREATE TYPE api_key_status          AS ENUM ('active', 'revoked', 'expired');
CREATE TYPE token_revocation_reason AS ENUM ('logout', 'rotation', 'reuse_detected', 'admin_revoked', 'expired', 'password_reset', 'breakglass');
CREATE TYPE login_status            AS ENUM ('success', 'failure_bad_password', 'failure_mfa', 'failure_locked', 'failure_disabled', 'failure_unknown_identity', 'failure_other');
CREATE TYPE auth_method             AS ENUM ('password', 'sso_oidc', 'sso_saml', 'api_key', 'service_account_token', 'webauthn');
CREATE TYPE audit_actor_type        AS ENUM ('user', 'service_account', 'api_key', 'system');
CREATE TYPE audit_result            AS ENUM ('success', 'failure', 'denied');

-- ----------------------------------------------------------------------------
-- ORGANIZATIONS (tenants)
-- Root of the multi-tenancy hierarchy. Every principal, role, and group is
-- scoped to exactly one organization (system-wide roles excepted, see roles).
-- ----------------------------------------------------------------------------
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) NOT NULL,
    status      org_status   NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_organizations_slug UNIQUE (slug)
);

-- ----------------------------------------------------------------------------
-- USERS
-- Human principals. Password hash is nullable to allow SSO-only accounts.
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    email                 CITEXT       NOT NULL,
    username              VARCHAR(100),
    password_hash         VARCHAR(255),           -- NULL when auth is SSO-only
    password_algo         VARCHAR(50),             -- e.g. 'argon2id', 'bcrypt'
    password_updated_at   TIMESTAMPTZ,
    status                user_status  NOT NULL DEFAULT 'pending_verification',
    mfa_enabled           BOOLEAN      NOT NULL DEFAULT false,
    email_verified_at     TIMESTAMPTZ,
    failed_login_attempts SMALLINT     NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at            TIMESTAMPTZ,             -- soft delete
    CONSTRAINT uq_users_org_email UNIQUE (organization_id, email),
    CONSTRAINT ck_users_failed_attempts_nonneg CHECK (failed_login_attempts >= 0)
);

CREATE INDEX idx_users_organization_id ON users (organization_id);
CREATE INDEX idx_users_status          ON users (status) WHERE deleted_at IS NULL;
-- email lookups are case-insensitive "for free" via the citext column type,
-- and are already covered by the uq_users_org_email unique index above.

-- ----------------------------------------------------------------------------
-- PERMISSIONS
-- System-defined capabilities. Global (not tenant-scoped) because the set of
-- possible actions is defined by the application, not by customers.
-- resource + action is the natural key; name is a derived, indexed shorthand.
-- ----------------------------------------------------------------------------
CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    VARCHAR(100) NOT NULL,     -- e.g. 'secret', 'user', 'policy'
    action      VARCHAR(50)  NOT NULL,     -- e.g. 'read', 'write', 'delete'
    name        VARCHAR(160) GENERATED ALWAYS AS (resource || ':' || action) STORED,
    description VARCHAR(500),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_permissions_resource_action UNIQUE (resource, action)
);

-- ----------------------------------------------------------------------------
-- ROLES
-- organization_id is NULL for built-in system roles (e.g. "org_admin") shared
-- across all tenants; non-null for tenant-defined custom roles.
-- ----------------------------------------------------------------------------
CREATE TABLE roles (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name             VARCHAR(100) NOT NULL,
    description      VARCHAR(500),
    is_system_role   BOOLEAN      NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_roles_org_name UNIQUE (organization_id, name)
);

CREATE INDEX idx_roles_organization_id ON roles (organization_id);

-- ----------------------------------------------------------------------------
-- ROLE_PERMISSIONS  (roles <--> permissions, M:N)
-- ----------------------------------------------------------------------------
CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles(id)       ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission_id ON role_permissions (permission_id);

-- ----------------------------------------------------------------------------
-- GROUPS
-- Supports a self-referencing hierarchy (e.g. "Engineering" > "Platform Team").
-- ----------------------------------------------------------------------------
CREATE TABLE groups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_group_id  UUID REFERENCES groups(id) ON DELETE SET NULL,
    name             VARCHAR(150) NOT NULL,
    description      VARCHAR(500),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_groups_org_name UNIQUE (organization_id, name),
    CONSTRAINT ck_groups_not_own_parent CHECK (parent_group_id IS DISTINCT FROM id)
);

CREATE INDEX idx_groups_organization_id ON groups (organization_id);
CREATE INDEX idx_groups_parent_group_id ON groups (parent_group_id);

-- ----------------------------------------------------------------------------
-- GROUP_MEMBERS  (users <--> groups, M:N)
-- ----------------------------------------------------------------------------
CREATE TABLE group_members (
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX idx_group_members_user_id ON group_members (user_id);

-- ----------------------------------------------------------------------------
-- GROUP_ROLES  (groups <--> roles, M:N) — roles inherited via group membership
-- ----------------------------------------------------------------------------
CREATE TABLE group_roles (
    group_id    UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX idx_group_roles_role_id ON group_roles (role_id);

-- ----------------------------------------------------------------------------
-- USER_ROLES  (users <--> roles, M:N) — direct role assignment
-- expires_at supports time-bound / just-in-time privileged access grants.
-- ----------------------------------------------------------------------------
CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,          -- NULL = permanent grant
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT ck_user_roles_expiry_future CHECK (expires_at IS NULL OR expires_at > assigned_at)
);

CREATE INDEX idx_user_roles_role_id    ON user_roles (role_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles (expires_at) WHERE expires_at IS NOT NULL;

-- ----------------------------------------------------------------------------
-- SERVICE_ACCOUNTS
-- Non-human, machine-identity principals (workloads, pipelines, integrations).
-- ----------------------------------------------------------------------------
CREATE TABLE service_accounts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name             VARCHAR(150) NOT NULL,
    description      VARCHAR(500),
    status           service_account_status NOT NULL DEFAULT 'active',
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_service_accounts_org_name UNIQUE (organization_id, name)
);

CREATE INDEX idx_service_accounts_organization_id ON service_accounts (organization_id);

-- ----------------------------------------------------------------------------
-- SERVICE_ACCOUNT_ROLES  (service_accounts <--> roles, M:N)
-- ----------------------------------------------------------------------------
CREATE TABLE service_account_roles (
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    role_id             UUID NOT NULL REFERENCES roles(id)            ON DELETE CASCADE,
    assigned_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (service_account_id, role_id)
);

CREATE INDEX idx_service_account_roles_role_id ON service_account_roles (role_id);

-- ----------------------------------------------------------------------------
-- API_KEYS
-- Owned by exactly one principal: a user OR a service account (never both,
-- never neither) — enforced by the CHECK constraint below.
-- Only a hash of the secret is stored; key_prefix is a short, non-secret
-- lookup/display identifier (cf. Stripe-style "sk_live_abcd...").
-- ----------------------------------------------------------------------------
CREATE TABLE api_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_user_id           UUID REFERENCES users(id)             ON DELETE CASCADE,
    owner_service_account_id UUID REFERENCES service_accounts(id) ON DELETE CASCADE,
    name                    VARCHAR(150) NOT NULL,
    key_prefix              VARCHAR(16)  NOT NULL,
    key_hash                VARCHAR(255) NOT NULL,
    status                  api_key_status NOT NULL DEFAULT 'active',
    last_used_at            TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at              TIMESTAMPTZ,
    revoked_reason          VARCHAR(255),
    CONSTRAINT uq_api_keys_key_hash UNIQUE (key_hash),
    CONSTRAINT ck_api_keys_single_owner CHECK (
        (owner_user_id IS NOT NULL AND owner_service_account_id IS NULL) OR
        (owner_user_id IS NULL AND owner_service_account_id IS NOT NULL)
    )
);

CREATE INDEX idx_api_keys_organization_id          ON api_keys (organization_id);
CREATE INDEX idx_api_keys_owner_user_id            ON api_keys (owner_user_id) WHERE owner_user_id IS NOT NULL;
CREATE INDEX idx_api_keys_owner_service_account_id ON api_keys (owner_service_account_id) WHERE owner_service_account_id IS NOT NULL;
CREATE INDEX idx_api_keys_key_prefix               ON api_keys (key_prefix);
CREATE INDEX idx_api_keys_status_expires           ON api_keys (status, expires_at);

-- ----------------------------------------------------------------------------
-- API_KEY_PERMISSIONS  (api_keys <--> permissions, M:N)
-- Direct, narrow scopes on a key — deliberately independent of the owner's
-- roles, so a key can be scoped tighter than the principal that created it.
-- ----------------------------------------------------------------------------
CREATE TABLE api_key_permissions (
    api_key_id    UUID NOT NULL REFERENCES api_keys(id)     ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id)  ON DELETE CASCADE,
    PRIMARY KEY (api_key_id, permission_id)
);

CREATE INDEX idx_api_key_permissions_permission_id ON api_key_permissions (permission_id);

-- ----------------------------------------------------------------------------
-- SESSIONS
-- One row per authenticated human session (web/CLI). Only a hash of the
-- session/bearer token is stored.
-- ----------------------------------------------------------------------------
CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(255) NOT NULL,
    ip_address         INET,
    user_agent         VARCHAR(500),
    device_fingerprint VARCHAR(255),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revoked_reason      token_revocation_reason,
    CONSTRAINT uq_sessions_token_hash UNIQUE (session_token_hash),
    CONSTRAINT ck_sessions_expiry_future CHECK (expires_at > created_at)
);

CREATE INDEX idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at) WHERE revoked_at IS NULL;

-- ----------------------------------------------------------------------------
-- REFRESH_TOKENS
-- Tied to the session that minted them. family_id + parent_token_id encode
-- the rotation chain so reuse of a superseded token can be detected and the
-- whole family revoked (standard refresh-token-rotation defense).
-- ----------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id         UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id            UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    token_hash         VARCHAR(255) NOT NULL,
    family_id          UUID NOT NULL,
    parent_token_id    UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revoked_reason     token_revocation_reason,
    replaced_by_token_id UUID REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT ck_refresh_tokens_expiry_future CHECK (expires_at > issued_at)
);

CREATE INDEX idx_refresh_tokens_user_id    ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens (session_id);
CREATE INDEX idx_refresh_tokens_family_id  ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at) WHERE revoked_at IS NULL;

-- ----------------------------------------------------------------------------
-- LOGIN_HISTORY
-- One row per authentication attempt, success or failure. user_id is
-- nullable because an attempt against an unknown identity must still be
-- recorded (brute-force / enumeration detection); attempted_identifier
-- preserves the raw input in that case.
-- ----------------------------------------------------------------------------
CREATE TABLE login_history (
    id                   BIGSERIAL PRIMARY KEY,
    organization_id      UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id              UUID REFERENCES users(id) ON DELETE SET NULL,
    attempted_identifier VARCHAR(255),
    status               login_status NOT NULL,
    auth_method          auth_method  NOT NULL,
    ip_address           INET,
    user_agent           VARCHAR(500),
    session_id           UUID REFERENCES sessions(id) ON DELETE SET NULL,
    occurred_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_login_history_user_occurred ON login_history (user_id, occurred_at DESC);
CREATE INDEX idx_login_history_ip_occurred   ON login_history (ip_address, occurred_at DESC);
CREATE INDEX idx_login_history_org_occurred  ON login_history (organization_id, occurred_at DESC);

-- ----------------------------------------------------------------------------
-- AUDIT_LOGS
-- Immutable record of every security-relevant action. actor_type/actor_id is
-- a deliberate polymorphic reference (a user, a service account, an API key,
-- or the system itself can be the actor) — it is indexed but NOT a foreign
-- key, because no single parent table can satisfy it and audit rows must
-- outlive the deletion of the actor they describe. prev_hash/record_hash
-- form a hash chain for tamper-evidence. metadata never contains secret
-- values, only descriptive context (path, identity, timestamp, action).
-- ----------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id               BIGSERIAL PRIMARY KEY,
    organization_id  UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_type       audit_actor_type NOT NULL,
    actor_id         UUID,                 -- polymorphic: users.id / service_accounts.id / api_keys.id / NULL for system
    action           VARCHAR(150) NOT NULL, -- e.g. 'role.assign', 'user.disable'
    resource_type    VARCHAR(100),
    resource_id      VARCHAR(255),
    result           audit_result NOT NULL,
    ip_address       INET,
    metadata         JSONB,
    prev_hash        VARCHAR(64),
    record_hash      VARCHAR(64) NOT NULL,
    occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_org_occurred      ON audit_logs (organization_id, occurred_at DESC);
CREATE INDEX idx_audit_logs_actor             ON audit_logs (actor_type, actor_id);
CREATE INDEX idx_audit_logs_resource          ON audit_logs (resource_type, resource_id);
CREATE INDEX idx_audit_logs_occurred_at       ON audit_logs (occurred_at DESC);
