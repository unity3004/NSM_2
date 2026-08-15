-- Seeds the one system-wide role bootstrap grants to the first
-- administrator (see service.BootstrapService) and the permissions that
-- back the API surface that already exists today (users, audit log
-- reads). This is deliberately not an exhaustive permission catalog for
-- every resource this schema anticipates (secrets, groups, service
-- accounts, API keys, role management) — those get seeded permissions
-- when the subsystems/handlers that actually check them are built, the
-- same "don't model a capability that doesn't exist yet" principle
-- entity.AuthenticatedIdentity's own doc comment already applies
-- elsewhere in this codebase.
--
-- Fixed, well-known IDs (not gen_random_uuid()) for the same reason
-- test/fixtures/organizations.sql uses one: bootstrap's Go code needs a
-- stable ID to grant by, without a lookup-by-name race of its own.
INSERT INTO roles (id, organization_id, name, description, is_system_role)
VALUES (
    '00000000-0000-4000-9000-000000000001',
    NULL,
    'Platform Administrator',
    'Full administrative access, granted automatically to the first account created during platform bootstrap.',
    true
);

INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000101', 'user',      'create', 'Create user accounts'),
    ('00000000-0000-4000-9000-000000000102', 'user',      'read',   'View user accounts'),
    ('00000000-0000-4000-9000-000000000103', 'user',      'update', 'Modify user accounts'),
    ('00000000-0000-4000-9000-000000000104', 'user',      'delete', 'Remove user accounts'),
    ('00000000-0000-4000-9000-000000000105', 'user',      'list',   'List user accounts'),
    ('00000000-0000-4000-9000-000000000106', 'audit_log', 'read',   'View audit log entries');

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000001', id FROM permissions
WHERE id IN (
    '00000000-0000-4000-9000-000000000101',
    '00000000-0000-4000-9000-000000000102',
    '00000000-0000-4000-9000-000000000103',
    '00000000-0000-4000-9000-000000000104',
    '00000000-0000-4000-9000-000000000105',
    '00000000-0000-4000-9000-000000000106'
);
