-- Three more system-wide roles, alongside the existing "Platform
-- Administrator" (000021) — which fills the "Administrator" role this
-- sprint's own authorization examples name (users:create -> ALLOWED):
-- no second, confusingly-duplicate "Administrator" role is created here.
--
-- Grants below are this migration's own defensible reading of a spec
-- that names two of these roles' grants explicitly and one only by what
-- it must NOT be able to do:
--   - Security Engineer's grant is copied verbatim from the
--     specification's own Role Detail example (secrets:read,
--     secrets:create, secrets:update, audit:read — deliberately no
--     secrets:delete, no user/role management).
--   - Auditor gets exactly what its name implies and nothing that
--     mutates anything: audit:read (its purpose), plus users:read and
--     roles:read (visibility needed to audit who has what access,
--     without the ability to change it).
--   - Developer gets secrets:read only — enough to build software
--     against real secret values once the Secrets Engine exists, nothing
--     administrative. This satisfies the specification's one explicit
--     assertion about this role (users:create -> DENIED) by simply never
--     granting it, the same way Auditor's denial works.
INSERT INTO roles (id, organization_id, name, description, is_system_role) VALUES
    ('00000000-0000-4000-9000-000000000002', NULL, 'Security Engineer', 'Manages secrets and reviews access; no user or role administration.', true),
    ('00000000-0000-4000-9000-000000000003', NULL, 'Developer',         'Reads secret values needed to build and run applications.',           true),
    ('00000000-0000-4000-9000-000000000004', NULL, 'Auditor',           'Read-only visibility across users, roles, and the audit log.',        true);

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000002', id FROM permissions
WHERE (resource, action) IN (('secrets', 'read'), ('secrets', 'create'), ('secrets', 'update'), ('audit', 'read'));

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000003', id FROM permissions
WHERE (resource, action) IN (('secrets', 'read'));

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000004', id FROM permissions
WHERE (resource, action) IN (('audit', 'read'), ('users', 'read'), ('roles', 'read'));
