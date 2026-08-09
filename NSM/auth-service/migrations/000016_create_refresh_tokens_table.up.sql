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
