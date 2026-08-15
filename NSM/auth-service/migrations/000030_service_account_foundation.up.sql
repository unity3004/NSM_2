-- Sprint 5 Task 1: Service Accounts & Machine Identity Foundation.
--
-- service_accounts, service_account_roles, api_keys, and api_key_permissions
-- already exist (000011-000014) — this migration is deliberately small,
-- filling the one real gap inspection found rather than re-modeling
-- anything: those tables, entity.ServiceAccount/entity.APIKey, and their
-- repository interfaces were already fully designed, just never given a
-- Postgres implementation or wired into the service/handler layers.

-- last_authenticated_at: the one column entity.ServiceAccount's Go struct
-- doesn't yet have a home for. Nullable — a freshly created service account
-- has never authenticated — and updated on every successful machine
-- authentication (see ServiceAccountService.Authenticate), the same
-- "last_used_at touched on use, never on issuance" convention api_keys
-- already established for its own last_used_at column.
ALTER TABLE service_accounts ADD COLUMN last_authenticated_at TIMESTAMPTZ;

-- Permission catalog additions this sprint's admin surface actually checks.
-- Two resources, not one: service_accounts (lifecycle: create/read/update/
-- delete/disable) and api_keys (issuing/revoking/rotating the credentials
-- api_keys already models generically for either a user or a service
-- account owner — see entity.APIKey's own doc comment) — the same
-- deliberate separation secret_policies (000028) already established from
-- secrets itself: a role that can administer a service account's identity
-- is not automatically a role that can mint credentials for it.
-- service_accounts:disable covers both disabling and re-enabling,
-- mirroring users:disable (000022). api_keys:delete is revocation
-- (auth-service-openapi.yaml's own DELETE /api-keys/{id} — there is no
-- separate hard-delete of an api_keys row anywhere in this codebase);
-- api_keys:rotate is this sprint's own additive extension to that spec's
-- existing /api-keys resource (see internal/handler/http/api_key_handler.go's
-- own doc comment).
INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000130', 'service_accounts', 'create',  'Create a service account'),
    ('00000000-0000-4000-9000-000000000131', 'service_accounts', 'read',    'View service account metadata, role, and policy assignments'),
    ('00000000-0000-4000-9000-000000000132', 'service_accounts', 'update',  'Rename or edit a service account''s description'),
    ('00000000-0000-4000-9000-000000000133', 'service_accounts', 'delete',  'Permanently delete a service account'),
    ('00000000-0000-4000-9000-000000000134', 'service_accounts', 'disable', 'Disable or re-enable a service account'),
    ('00000000-0000-4000-9000-000000000135', 'api_keys',         'create',  'Issue a new API key/credential'),
    ('00000000-0000-4000-9000-000000000136', 'api_keys',         'read',    'View API key/credential metadata (never the secret)'),
    ('00000000-0000-4000-9000-000000000137', 'api_keys',         'delete',  'Revoke an API key/credential'),
    ('00000000-0000-4000-9000-000000000138', 'api_keys',         'rotate',  'Rotate an API key/credential');

-- Platform Administrator gets every new permission — the same "the one role
-- meant to have full access gets everything new" rule every prior catalog
-- extension in this codebase already applied (000022, 000023, 000028).
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000001', id FROM permissions
WHERE id IN (
    '00000000-0000-4000-9000-000000000130',
    '00000000-0000-4000-9000-000000000131',
    '00000000-0000-4000-9000-000000000132',
    '00000000-0000-4000-9000-000000000133',
    '00000000-0000-4000-9000-000000000134',
    '00000000-0000-4000-9000-000000000135',
    '00000000-0000-4000-9000-000000000136',
    '00000000-0000-4000-9000-000000000137',
    '00000000-0000-4000-9000-000000000138'
);
