CREATE TABLE api_key_permissions (
    api_key_id    UUID NOT NULL REFERENCES api_keys(id)     ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id)  ON DELETE CASCADE,
    PRIMARY KEY (api_key_id, permission_id)
);

CREATE INDEX idx_api_key_permissions_permission_id ON api_key_permissions (permission_id);
