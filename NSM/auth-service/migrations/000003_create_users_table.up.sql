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
