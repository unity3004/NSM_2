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
