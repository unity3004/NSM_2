CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,          -- NULL = permanent grant
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT ck_user_roles_expiry_future CHECK (expires_at IS NULL OR expires_at > assigned_at)
);

CREATE INDEX idx_user_roles_role_id    ON user_roles (role_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles (expires_at) WHERE expires_at IS NOT NULL;
