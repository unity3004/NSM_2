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
