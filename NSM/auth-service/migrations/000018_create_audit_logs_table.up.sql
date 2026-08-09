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
