# Enterprise Authentication Service — Database Design

Companion explanation for [`auth_service_schema.sql`](./auth_service_schema.sql) (PostgreSQL 15+).

## 1. Design principles

- **Normalized to 3NF.** Every non-key column depends on the whole primary key and nothing but the key. Many-to-many relationships (user↔role, role↔permission, group↔role, etc.) are broken out into junction tables instead of repeated or array-packed columns.
- **Multi-tenant from the start.** An `organizations` table roots the hierarchy because "enterprise" implies more than one customer/business-unit sharing the platform. This wasn't in the requested table list but is required to scope users, roles, and groups correctly — remove it and treat the whole schema as single-tenant if that's not your case.
- **Secrets are never stored — only hashes.** `users.password_hash`, `sessions.session_token_hash`, `refresh_tokens.token_hash`, and `api_keys.key_hash` store only irreversible hashes (or, for password, a salted KDF output). The raw token/key is shown to the caller exactly once at issuance and never persisted.
- **RBAC with two paths to a role:** direct assignment (`user_roles`) and inherited-via-group (`group_roles`), mirroring how real IAM systems (Okta, AWS IAM, Vault) work — an admin can grant a role to one person or to an entire team at once.
- **Human vs. machine identity are separate principals** (`users` vs. `service_accounts`), each of which can hold roles and own API keys, but through their own junction tables — a service account is never "a user with a flag."

## 2. Entity overview

| Table | Purpose |
|---|---|
| `organizations` | Tenant boundary — everything else hangs off this. |
| `users` | Human principals (employees, admins). |
| `permissions` | Atomic capabilities (`resource:action`), global and system-defined. |
| `roles` | Named, reusable bundles of permissions; tenant-scoped or system-wide. |
| `role_permissions` | Junction: which permissions a role grants. |
| `groups` | Organizational units of users (teams, departments); hierarchical. |
| `group_members` | Junction: which users belong to which group. |
| `group_roles` | Junction: which roles a group grants to its members. |
| `user_roles` | Junction: roles assigned directly to a user, with optional expiry. |
| `service_accounts` | Machine/workload principals (pipelines, integrations). |
| `service_account_roles` | Junction: roles assigned to a service account. |
| `api_keys` | Long-lived credential issued to a user *or* a service account. |
| `api_key_permissions` | Junction: narrow scopes attached directly to one key. |
| `sessions` | An authenticated human session (web/CLI login). |
| `refresh_tokens` | Rotating tokens used to mint new access tokens for a session. |
| `login_history` | Append-only record of every authentication attempt. |
| `audit_logs` | Append-only record of every security-relevant action taken. |

## 3. Table-by-table detail

### `organizations`
The tenant/customer boundary. `slug` is the URL-safe, unique handle used in routing (`acme.authservice.com` style). `status` lets you suspend a tenant (e.g., non-payment) without deleting its data — deletion is a separate, deliberate operation.

### `users`
The human principal. Key normalization decisions:
- `password_hash` and `password_algo` are nullable together, because an SSO-only account has no local password at all — storing `NULL` rather than an empty string avoids a false "has password" signal.
- `failed_login_attempts` / `locked_until` support account lockout without a separate table, since they're 1:1 attributes of the user, not a repeating group.
- `deleted_at` is a soft-delete marker: audit logs and login history reference `user_id`, so hard-deleting a user would either orphan or force-cascade years of compliance history. Soft delete preserves referential integrity while letting the app hide the account.
- Unique on `(organization_id, email)` — the same email can exist in two different tenants (e.g., a contractor with `same@name.com` at two customer orgs), but not twice inside one tenant.

### `permissions`
The atomic unit of access: a `resource` (`"secret"`, `"user"`, `"billing"`) paired with an `action` (`"read"`, `"write"`, `"delete"`, `"rotate"`). `name` is a **generated column** (`resource || ':' || action`) — this avoids storing a redundant, independently-editable copy of data that's fully determined by two other columns (a textbook transitive-dependency violation if stored as a plain column). Permissions are global, not per-tenant: a platform team defines the finite set of things the system can do; tenants only choose how to *bundle* them into roles.

### `roles`
A named bundle of permissions. `organization_id` is nullable on purpose: system roles (`org_admin`, `read_only`) ship with `organization_id = NULL` and are visible to every tenant, while a tenant's custom role (`payments-oncall`) is scoped to that tenant only. This is why `role_permissions`, `user_roles`, etc. reference `roles.id` rather than duplicating role definitions per tenant.

### `role_permissions`
Pure junction table resolving the roles↔permissions many-to-many. Composite primary key `(role_id, permission_id)` — a role can't have the same permission twice, and the pair *is* the identity of the row, so no surrogate key is needed.

### `groups`
A collection of users (team, department, business unit). `parent_group_id` self-references `groups.id` to support nesting ("Platform Team" under "Engineering"), with `ON DELETE SET NULL` so deleting a parent promotes children to top-level rather than cascading deletion through an entire org chart. A `CHECK` constraint blocks a group from being its own parent; deeper cycles (A→B→A) are an application-level invariant, not practical to enforce in a `CHECK`.

### `group_members`
Junction resolving users↔groups. `added_by` records who performed the add for accountability, separate from `added_at`.

### `group_roles`
Junction resolving groups↔roles — this is how "everyone on the Payments team automatically gets the `payments-read` role" is modeled, without writing one `user_roles` row per team member. A user's *effective* roles are therefore the union of `user_roles` (direct) and `group_roles` (via every group in `group_members` for that user).

### `user_roles`
Direct, per-user role grants. `expires_at` (nullable) is what makes time-bound / just-in-time privileged access possible — grant a role for 4 hours during an incident, and a scheduled job (or a `WHERE expires_at < now()` filter at read time) treats it as gone without anyone having to remember to revoke it. `assigned_by` gives an audit-friendly answer to "who granted this."

### `service_accounts`
The machine-identity equivalent of `users`, deliberately kept as its own table rather than a row-type flag on `users` — a service account has no password, no MFA, no session in the human sense, and modeling it separately means those columns are never nullable-for-half-the-table on `users`.

### `service_account_roles`
Junction resolving service_accounts↔roles, structurally identical to `user_roles` minus the expiry (machine credentials are typically governed by the API key's own `expires_at` instead, not a separate grant window — add an `expires_at` here too if your service accounts need JIT elevation the same way users do).

### `api_keys`
A long-lived bearer credential. Two normalization points:
- Only `key_hash` is stored (never the raw key); `key_prefix` is a short, non-secret identifier (e.g., first 8 characters) so a UI can show "Key `sk_live_a1b2...`" for identification without ever displaying — or being able to reconstruct — the secret.
- **Exactly one owner.** `owner_user_id` and `owner_service_account_id` are both nullable, but a `CHECK` constraint enforces that precisely one is set. This is the standard relational pattern for "belongs to exactly one of several types" without a polymorphic FK — two nullable FK columns plus a mutual-exclusion check, each still a real, enforced foreign key.

### `api_key_permissions`
Junction giving a key its own scopes, independent of whatever roles its owner holds. This matters operationally: a developer with broad `user_roles` should still be able to mint a narrowly-scoped CI key rather than one that inherits their full privilege — least-privilege at the credential level, not just the principal level.

### `sessions`
One row per browser/CLI login. Stores only `session_token_hash`, plus enough metadata (`ip_address`, `user_agent`, `device_fingerprint`) to power "your active sessions" UI and anomaly detection. `revoked_at`/`revoked_reason` let a session be killed (logout, admin action, breach response) without deleting the row — you want the history of "this session existed and was revoked at time X," not a silent disappearance.

### `refresh_tokens`
Each refresh token belongs to exactly one `session_id` (and, denormalized for query convenience, `user_id` — technically derivable via `sessions.user_id` but kept directly here because refresh-token validation is a hot path that shouldn't require a join). The rotation-chain columns are the important design point:
- `family_id` groups every token descended from one original login.
- `parent_token_id` / `replaced_by_token_id` form a linked list through that family as the client rotates tokens on each refresh.
- If a token is presented that's already been superseded (its `replaced_by_token_id` is set), that's a signature of token theft — the standard response is to revoke the entire `family_id`, which this structure makes a single indexed query.

### `login_history`
An append-only ledger of *every* authentication attempt, successful or not. `user_id` is nullable because an attempt against a nonexistent account must still be logged for brute-force/credential-stuffing detection — `attempted_identifier` preserves what was typed when there's no user row to point to. This table is intentionally separate from `audit_logs`: login attempts are extremely high-volume and narrowly-shaped (auth only), whereas audit logs cover arbitrary actions across the whole system — mixing them would force one table to carry columns that are meaningless for the other's rows.

### `audit_logs`
The tamper-evident, compliance-facing ledger of security-relevant actions (role changes, key revocations, policy edits, secret access — never secret *values*, only metadata). Two intentional departures from strict FK normalization, both called out with comments in the DDL:
- `actor_type` + `actor_id` is a **polymorphic reference** — the actor can be a user, a service account, an API key, or the system itself. No single foreign key can point at four different parent tables, so `actor_id` is indexed but not FK-constrained; the alternative (four nullable FK columns, one per actor type, like `api_keys` does for its two owner types) was rejected here because audit rows must survive the deletion of the actor they describe, and a real FK would force `ON DELETE SET NULL`/`RESTRICT` choices that either lose the actor's identity or block deleting old service accounts.
- `prev_hash` / `record_hash` implement a hash chain (each row's hash covers its own content plus the previous row's hash), giving tamper-evidence: altering a historical row breaks every subsequent hash, which is checkable without a blockchain or external ledger.

## 4. Relationship summary

```
organizations 1───* users
organizations 1───* roles          (nullable org_id = system-wide role)
organizations 1───* groups
organizations 1───* service_accounts
organizations 1───* api_keys

users       *───* roles            via user_roles       (+ expires_at)
users       *───* groups           via group_members
groups      *───* roles            via group_roles
roles       *───* permissions      via role_permissions
service_accounts *───* roles       via service_account_roles

users            1───* sessions
sessions         1───* refresh_tokens
refresh_tokens   1───* refresh_tokens   (self-ref: parent_token_id / replaced_by_token_id)
groups           1───* groups           (self-ref: parent_group_id)

users            1───* login_history   (nullable — unknown-identity attempts have no user_id)
users            1───* api_keys        (nullable owner)
service_accounts 1───* api_keys        (nullable owner; exactly one owner type via CHECK)
api_keys         *───* permissions     via api_key_permissions

{users | service_accounts | api_keys | system} 1───* audit_logs   (polymorphic actor_type/actor_id)
```

**Effective permissions for a user**, as a single conceptual query:
```
permissions granted =
    (role_permissions of user_roles for this user, where not expired)
  ∪ (role_permissions of group_roles for every group this user belongs to)
```

## 5. Indexing & constraint strategy

- **Every FK column has a supporting index** on the "many" side that isn't already the leading column of its table's primary key (e.g., `idx_role_permissions_permission_id`, `idx_user_roles_role_id`) — junction tables are queried in both directions ("permissions of this role" and "roles containing this permission"), and only one direction is free from the composite PK.
- **Hot lookup columns are unique-indexed**: `session_token_hash`, `refresh_tokens.token_hash`, `api_keys.key_hash` — these are looked up on every request, so validation is a single unique-index hit.
- **Partial indexes** trim index size to what's actually queried: `idx_sessions_expires_at` and `idx_refresh_tokens_expires_at` only index non-revoked rows (`WHERE revoked_at IS NULL`), which is what cleanup/expiry jobs scan.
- **Time-ordered indexes** (`login_history`, `audit_logs`) are `(dimension, occurred_at DESC)` composites, matching the actual access pattern: "show me this user's/org's/IP's recent history," newest first.
- **CHECK constraints enforce invariants the type system can't**: exactly-one-owner on `api_keys`, expiry-after-creation on `sessions`/`refresh_tokens`/`user_roles`, and no-self-parenting on `groups`.
- **ON DELETE behavior is chosen per relationship**, not defaulted uniformly:
  - `CASCADE` where the child is meaningless without the parent (a session's refresh tokens, a role's permission grants, a group's memberships).
  - `SET NULL` where the parent is optional context that shouldn't block deletion (`groups.parent_group_id`, `login_history.user_id`, `audit_logs.organization_id`).
  - `RESTRICT` where deleting the parent should be a deliberate, blocked operation until dependents are handled (`users.organization_id` — you can't delete a tenant out from under its users by accident).

## 6. Known extension points (not built, deliberately)

- **MFA factors** (TOTP secrets, WebAuthn credentials) would be their own `mfa_factors` table (user_id FK, factor_type, encrypted_secret) rather than columns on `users`, since a user can register more than one factor — this schema stops at the `users.mfa_enabled` flag since MFA detail wasn't in scope.
- **Password history** (for reuse-prevention policies) would be a `password_history` table keyed by `user_id`, append-only.
- **Delegated/break-glass access** could reuse `user_roles.expires_at` plus an `audit_logs` entry per grant, rather than a new table — the primitives here already cover it.
