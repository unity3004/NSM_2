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
