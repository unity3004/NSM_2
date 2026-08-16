CREATE TABLE service_account_roles (
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    role_id             UUID NOT NULL REFERENCES roles(id)            ON DELETE CASCADE,
    assigned_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (service_account_id, role_id)
);

CREATE INDEX idx_service_account_roles_role_id ON service_account_roles (role_id);
