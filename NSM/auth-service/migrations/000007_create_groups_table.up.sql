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
