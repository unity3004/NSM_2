-- Sprint 4 Task 2 — path-scoped secret authorization. Answers "does this
-- user's role hold a policy that grants ACTION on this specific secret
-- path," layered on top of (never replacing) the existing secrets:*
-- permission check role_permissions already answers ("does this user
-- hold secrets:read at all"). See internal/policy's package doc comment
-- for the evaluation semantics and internal/service/secret_policy_service.go
-- for how this schema is queried.
--
-- Mirrors roles/role_permissions/user_roles' own normalized shape rather
-- than inventing a new one: secret_policies is to secret_policy_rules
-- (and, through them, secret_policy_rule_actions) what roles is to
-- role_permissions — a named, reusable bundle, this time of path grants
-- instead of resource:action grants. secret_policy_role_assignments is to
-- secret_policies what user_roles is to roles: the grant itself. Like
-- roles, secret_policies tracks no created_by column — "who created this"
-- is what audit_logs.actor_id (the policy.created event) already records;
-- duplicating that as a table column isn't a pattern this schema uses for
-- administrative RBAC-shaped entities (contrast secrets/secret_versions,
-- genuinely user-owned data, which do carry created_by).
--
-- No secret_policy_group_assignments table: entity.Group/GroupRole exist
-- in this schema but internal/repository/postgres/rbac_repository.go's
-- UserHasPermission/UserPermissions — the actual, live permission-check
-- path — has never queried through group_roles/group_members at all;
-- there is no GroupService, no /v1/groups route, and no group-based grant
-- anywhere in the currently-enforced RBAC decision. Adding group-scoped
-- policy assignment here would require first wiring groups into base RBAC
-- itself, which is a change to the existing RBAC system this task is
-- explicit about not making. Role-based assignment alone matches what
-- this codebase's authorization actually does today; see this sprint's
-- final report for this as a documented, deliberate scope decision.

-- organization_id is NULLABLE, matching roles.organization_id's own
-- nullability exactly, and for the identical reason: a policy assigned to
-- a system-wide role (Platform Administrator, Security Engineer, Developer
-- — all organization_id IS NULL) must itself apply across every tenant a
-- member of that role belongs to, not just one arbitrarily-chosen
-- organization. NULL means "platform-wide policy, usable by any
-- organization whose user holds an assigned role"; non-NULL means
-- "tenant-defined policy, visible only within that organization" — the
-- same split RoleRepository.List's own doc comment already documents for
-- roles.
CREATE TABLE secret_policies (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name             VARCHAR(100) NOT NULL,
    description      VARCHAR(500),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_secret_policies_org_name UNIQUE (organization_id, name)
);

CREATE INDEX idx_secret_policies_organization_id ON secret_policies (organization_id);

-- One row per (path_pattern, effect) a policy grants or forbids;
-- path_pattern is validated at the application layer
-- (util.ValidatePolicyPathPattern) the same way secrets.path's own
-- character rules are — see that function's own doc comment for exactly
-- what "*" / "<path>/*" / an exact path may contain. 1040, not 1024
-- (MaxSecretPathLength): room for the literal "/*" suffix on top of the
-- longest allowed non-wildcard prefix, so the column itself is never the
-- reason a maximally-long, otherwise-valid pattern is rejected.
CREATE TYPE secret_policy_effect AS ENUM ('allow', 'deny'); -- policy.Effect

CREATE TABLE secret_policy_rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id    UUID NOT NULL REFERENCES secret_policies(id) ON DELETE CASCADE,
    path_pattern VARCHAR(1040) NOT NULL,
    effect       secret_policy_effect NOT NULL DEFAULT 'allow',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_secret_policy_rules_path_pattern_not_empty CHECK (length(path_pattern) > 0)
);

CREATE INDEX idx_secret_policy_rules_policy_id ON secret_policy_rules (policy_id);

-- Actions a rule grants/forbids — a normalized junction table, not a
-- native array column: no other table in this schema stores a
-- multi-valued attribute as an array (role_permissions/group_roles/
-- user_roles are all junction tables too), and this keeps each action
-- independently indexable and constrainable the same way.
CREATE TYPE secret_policy_action AS ENUM ('read', 'create', 'update', 'delete', 'list'); -- policy.Action

CREATE TABLE secret_policy_rule_actions (
    rule_id UUID NOT NULL REFERENCES secret_policy_rules(id) ON DELETE CASCADE,
    action  secret_policy_action NOT NULL,
    PRIMARY KEY (rule_id, action)
);

-- The grant itself — a policy applies to a role's members exactly the way
-- a permission applies to a role's members via role_permissions.
CREATE TABLE secret_policy_role_assignments (
    policy_id   UUID NOT NULL REFERENCES secret_policies(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id)            ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, role_id)
);

CREATE INDEX idx_secret_policy_role_assignments_role_id ON secret_policy_role_assignments (role_id);

-- --- Backward compatibility -------------------------------------------
-- The objective is explicit: "if no applicable policy grants access,
-- DENY — never default to allow." Enforcing that from this migration
-- forward, with zero seeded policies, would silently revoke every secret
-- access every existing role currently has via secrets:read/create/
-- update/delete/list (migrations 000022, 000023, 000025) — exactly the
-- "do not break existing... Secrets API" the objective also requires.
-- Seeding one platform-wide "Full Access" policy (path pattern "*", every
-- action, effect allow), assigned to every role that already holds
-- secrets:read, closes that gap: those roles' access is unchanged from
-- before this migration, and the deny-by-default mechanism this migration
-- introduces is exercised for real by any role that does NOT hold this
-- policy (or a narrower one), rather than only in tests. This mirrors
-- migration 000025's own "granted to exactly the roles that already hold
-- secrets:read" backfill technique exactly. Fixed, well-known IDs, the
-- same reason 000021/000023 use them: nothing here needs to look a row
-- up by name first.
INSERT INTO secret_policies (id, organization_id, name, description)
VALUES (
    '00000000-0000-4000-9000-000000000200', NULL, 'Full Access (system default)',
    'Grants every secret action on every path — seeded for backward compatibility with roles that already held unrestricted secrets:* permissions before path policies existed.'
);

INSERT INTO secret_policy_rules (id, policy_id, path_pattern, effect)
VALUES ('00000000-0000-4000-9000-000000000201', '00000000-0000-4000-9000-000000000200', '*', 'allow');

INSERT INTO secret_policy_rule_actions (rule_id, action)
VALUES
    ('00000000-0000-4000-9000-000000000201', 'read'),
    ('00000000-0000-4000-9000-000000000201', 'create'),
    ('00000000-0000-4000-9000-000000000201', 'update'),
    ('00000000-0000-4000-9000-000000000201', 'delete'),
    ('00000000-0000-4000-9000-000000000201', 'list');

-- ON CONFLICT DO NOTHING: a role that somehow already holds this exact
-- assignment (re-running this migration's data half against a database
-- that already has it via some other path) is a no-op, not an error.
INSERT INTO secret_policy_role_assignments (policy_id, role_id)
SELECT '00000000-0000-4000-9000-000000000200', rp.role_id
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE p.resource = 'secrets' AND p.action = 'read'
ON CONFLICT DO NOTHING;
