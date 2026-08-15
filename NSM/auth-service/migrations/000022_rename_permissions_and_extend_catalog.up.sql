-- Sprint 2.6 (000021) seeded this catalog using singular resource names
-- ('user', 'audit_log'), matching the singular convention audit_logs.resource_type
-- already used elsewhere. Sprint 2.7's own specification is explicit and
-- literal about plural resource names ('users:read', 'audit:read') for
-- the permissions an authorization system will actually check — and
-- nothing has checked any of these strings yet (no authorization
-- middleware existed before this migration's own sprint), so renaming
-- now, before either naming is load-bearing anywhere, is a rename, not a
-- breaking change. The permission IDs themselves are untouched — the
-- existing role_permissions grant to Platform Administrator
-- (000021_seed_platform_admin_role.up.sql) survives this migration
-- unchanged.
UPDATE permissions SET resource = 'users' WHERE resource = 'user';
UPDATE permissions SET resource = 'audit' WHERE resource = 'audit_log';

-- New permissions this sprint's user/role-management surface actually
-- checks. users:disable is deliberately the one permission that gates
-- *both* disabling and re-enabling a user (see service/user_service.go's
-- DisableUser/EnableUser) — enabling is the same "manage this account's
-- active/disabled status" capability as disabling, not a separate
-- capability with its own permission the specification never names.
-- roles:read/roles:update back the read-only Roles page and role-grant
-- endpoints respectively. secrets:create/read/update/delete are seeded
-- now, deliberately unchecked by anything until the Secrets Engine
-- itself exists (see that migration's own doc comment for the same
-- "don't model a capability that doesn't exist yet" principle applied to
-- users:create/read/update/delete/list originally) — seeding them here
-- rather than later is what "future-compatible with the Secrets Engine"
-- means concretely: that engine's first migration grants them to roles,
-- it does not need to invent them.
INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000107', 'users',   'disable', 'Disable or re-enable a user account'),
    ('00000000-0000-4000-9000-000000000108', 'roles',   'read',    'View roles and their permissions'),
    ('00000000-0000-4000-9000-000000000109', 'roles',   'update',  'Assign or remove role grants'),
    ('00000000-0000-4000-9000-000000000110', 'secrets', 'create',  'Create a secret (reserved for the Secrets Engine)'),
    ('00000000-0000-4000-9000-000000000111', 'secrets', 'read',    'Read a secret value (reserved for the Secrets Engine)'),
    ('00000000-0000-4000-9000-000000000112', 'secrets', 'update',  'Create a new secret version (reserved for the Secrets Engine)'),
    ('00000000-0000-4000-9000-000000000113', 'secrets', 'delete',  'Delete a secret or version (reserved for the Secrets Engine)');

-- Platform Administrator gets every new permission too — it is the one
-- role meant to have full access, the same reasoning
-- 000021_seed_platform_admin_role.up.sql already applied to the original six.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000001', id FROM permissions
WHERE id IN (
    '00000000-0000-4000-9000-000000000107',
    '00000000-0000-4000-9000-000000000108',
    '00000000-0000-4000-9000-000000000109',
    '00000000-0000-4000-9000-000000000110',
    '00000000-0000-4000-9000-000000000111',
    '00000000-0000-4000-9000-000000000112',
    '00000000-0000-4000-9000-000000000113'
);
