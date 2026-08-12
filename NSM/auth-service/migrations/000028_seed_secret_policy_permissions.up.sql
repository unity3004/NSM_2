-- Sprint 4 Task 2 — the permission catalog for policy administration
-- itself (create/read/update/delete a secret_policies row, assign/unassign
-- it to a role) — separate from secrets:* (which governs secret *values*,
-- not the policies that gate access to them), the same "policies are
-- their own resource, not folded into the resource they protect"
-- separation roles:* already keeps from users:*.
--
-- resource = 'secret_policies' (plural), matching this schema's
-- post-000022 convention (secrets, users, roles are all plural).
INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000120', 'secret_policies', 'create', 'Create a secret path-authorization policy'),
    ('00000000-0000-4000-9000-000000000121', 'secret_policies', 'read',   'View secret path-authorization policies'),
    ('00000000-0000-4000-9000-000000000122', 'secret_policies', 'update', 'Modify a secret path-authorization policy''s rules'),
    ('00000000-0000-4000-9000-000000000123', 'secret_policies', 'delete', 'Delete a secret path-authorization policy'),
    ('00000000-0000-4000-9000-000000000124', 'secret_policies', 'assign', 'Assign or unassign a secret path-authorization policy to/from a role');

-- Platform Administrator only — "authorized administrators," per the
-- objective, deliberately not extended to Security Engineer: that role
-- manages secret *values* (secrets:read/create/update), which is a
-- different capability from deciding which paths other roles may reach.
-- Widening this is a one-line follow-up migration if a future sprint's
-- own spec calls for it explicitly; nothing here forecloses that.
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-4000-9000-000000000001', id FROM permissions
WHERE id IN (
    '00000000-0000-4000-9000-000000000120',
    '00000000-0000-4000-9000-000000000121',
    '00000000-0000-4000-9000-000000000122',
    '00000000-0000-4000-9000-000000000123',
    '00000000-0000-4000-9000-000000000124'
);
