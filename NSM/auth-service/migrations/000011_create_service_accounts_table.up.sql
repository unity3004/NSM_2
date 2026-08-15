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
