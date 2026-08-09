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
