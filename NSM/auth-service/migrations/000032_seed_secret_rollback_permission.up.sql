-- Secret Versioning phase — the one net-new permission this phase
-- introduces. secret_versions, current_version, GetVersion/ListVersions/
-- CreateVersionIfCurrent (repository.SecretRepository) and the version-
-- aware CreateSecret/GetSecret/UpdateSecret (SecretService) already
-- existed before this migration; only rollback ("create a new version
-- whose value comes from an old one") is new, and it gets its own
-- capability rather than piggybacking on secrets:update — "read a secret's
-- history" must not imply "may overwrite the current value with an old
-- one," the same deliberate split 000025 already drew between
-- secrets:read and secrets:list.
INSERT INTO permissions (id, resource, action, description) VALUES
    ('00000000-0000-4000-9000-000000000115', 'secrets', 'rollback', 'Create a new secret version from a prior version''s value');

-- Granted to exactly the roles that already hold secrets:update (000021,
-- 000023: Platform Administrator, Security Engineer) — the same write
-- tier, since a rollback is achievable today by anyone holding
-- secrets:update simply by manually resubmitting an old value; this
-- permission only makes that same capability safer and auditable, it
-- does not hand out a new privilege tier. Developer (secrets:read only)
-- and Auditor (no secrets:* at all) deliberately do not gain it — "read
-- != rollback" per this phase's own requirement.
INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, '00000000-0000-4000-9000-000000000115'
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE p.resource = 'secrets' AND p.action = 'update';
