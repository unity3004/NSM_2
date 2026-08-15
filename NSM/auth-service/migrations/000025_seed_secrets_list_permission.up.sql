-- Sprint 3 Phase 3 (Secrets Service). 000022 seeded secrets:create/read/
-- update/delete but not secrets:list — an oversight flagged explicitly in
-- Phase 1's own final report and now needed for real: SecretService.ListSecrets
-- gates on it rather than reusing secrets:read, because listing paths and
-- reading a value are different capabilities worth being able to grant
-- separately (an auditor-style role might reasonably see what secrets
-- exist without being able to read any of their values) even though
-- every role that holds secrets:read today also gets secrets:list below.
INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000114', 'secrets', 'list', 'List secret paths and metadata, without reading values');

-- Granted to exactly the roles that already hold secrets:read
-- (000022, 000023): Platform Administrator, Security Engineer, Developer.
INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, '00000000-0000-4000-9000-000000000114'
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE p.resource = 'secrets' AND p.action = 'read';
