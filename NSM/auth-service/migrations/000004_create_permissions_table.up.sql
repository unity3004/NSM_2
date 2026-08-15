CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    VARCHAR(100) NOT NULL,     -- e.g. 'secret', 'user', 'policy'
    action      VARCHAR(50)  NOT NULL,     -- e.g. 'read', 'write', 'delete'
    name        VARCHAR(160) GENERATED ALWAYS AS (resource || ':' || action) STORED,
    description VARCHAR(500),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_permissions_resource_action UNIQUE (resource, action)
);
