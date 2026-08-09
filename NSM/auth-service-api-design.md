# Enterprise Authentication Service — REST API Design

Companion to [`auth-service-openapi.yaml`](./auth-service-openapi.yaml) (OpenAPI 3.1, the
authoritative machine-readable spec) and the earlier [`auth_service_schema.sql`](./auth_service_schema.sql) /
[`auth-service-database-schema.md`](./auth-service-database-schema.md). Every endpoint below maps
1:1 onto a table or junction table in that schema — there is no API surface here that doesn't
correspond to something the database can actually store.

## 1. Conventions

| Aspect | Decision |
|---|---|
| Base URL | `https://auth.example.com/v1` |
| Body format | `application/json`, fields in `snake_case` (matches column names 1:1) |
| Timestamps | ISO 8601 / RFC 3339, UTC (`2026-08-07T14:32:00Z`) |
| IDs | UUIDv4 strings, except `login_history.id` / `audit_logs.id` (opaque, backed by `BIGSERIAL`) |
| Tenancy | Inferred from the caller's access token (`org_id` claim) — no endpoint accepts an `organization_id` override |
| Auth | `Authorization: Bearer <jwt>` for people and minted service tokens; `X-Api-Key: <raw key>` only for the token-exchange endpoint |
| Pagination | Cursor-based: `?limit=20&cursor=...`, response includes `page.next_cursor` / `page.has_more` |
| Idempotency | `Idempotency-Key` header on creating `POST`s — replay returns the original response, not a duplicate |
| Authorization model | Every endpoint requires a `resource:action` permission (the exact string in `permissions.name`) |

**Why `snake_case` over `camelCase`:** the API is a thin layer over the schema; translating
`organization_id` to `organizationId` at the boundary buys nothing and costs a mapping step in
every client and every log line that needs to be cross-referenced against a SQL query.

**Why cursor pagination over offset:** `audit_logs` and `login_history` are append-only and can
grow into the tens of millions of rows per tenant; `OFFSET 500000` degrades linearly while a
cursor (typically the last row's `occurred_at` + `id`) stays flat.

## 2. Authentication & authorization

Three principal types can hold a bearer token, matching the three principal tables:

1. **Human users** — `POST /auth/login` (password) → `access_token` + `refresh_token`, backed by a
   row each in `sessions` and `refresh_tokens`.
2. **Service accounts** — `POST /service-accounts/{id}/token`, authenticated with `X-Api-Key`
   (a raw key checked against `api_keys.key_hash`), returns a short-lived `access_token` only — no
   session or refresh token is created, since machine callers just repeat the exchange.
3. **API keys used directly** — some integrations (CI runners, webhooks) present `X-Api-Key`
   straight to a resource endpoint rather than exchanging it for a JWT first; the gateway resolves
   the key to its owner and its own `api_key_permissions` scopes in the same way either path is
   evaluated.

Every request is authorized against the **union of the caller's effective permissions**: direct
`user_roles`, roles inherited via `group_roles`, and — for a request made with a raw API key —
intersected with that key's own `api_key_permissions` (a key can only ever narrow what its owner
can do, never widen it).

## 3. Error model

Every non-2xx response uses the same envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request failed validation.",
    "details": [
      { "field": "email", "issue": "must be a valid email address" }
    ],
    "request_id": "req_01J9X8V2QYUR6EZC1G5N3B7K4M"
  }
}
```

`details` is only present for multi-field validation failures; `request_id` is always present and
is what a caller pastes into a support ticket.

### HTTP status code conventions

| Code | Meaning here |
|---|---|
| `200 OK` | Successful `GET`, `PATCH`, or action endpoint |
| `201 Created` | Successful `POST` that created a row |
| `204 No Content` | Successful `DELETE`, or an action with nothing to return |
| `400 Bad Request` | Malformed request — invalid JSON, wrong content type, `occurred_after` after `occurred_before` |
| `401 Unauthorized` | Missing/invalid/expired token or API key, bad login credentials, expired or reused refresh token |
| `403 Forbidden` | Authenticated, but the policy engine denied it (missing permission, disabled account, wrong key owner) |
| `404 Not Found` | Resource doesn't exist, or exists in a different organization (never distinguished from "doesn't exist" — see §5) |
| `409 Conflict` | Unique constraint violation, duplicate membership/grant, or the `api_keys` owner `CHECK` constraint |
| `422 Unprocessable Entity` | The request is well-formed JSON but fails field-level validation |
| `423 Locked` | Account locked out after too many failed logins (`users.locked_until`) |
| `429 Too Many Requests` | Rate limit exceeded (brute-force protection, mainly on `/auth/login`) |
| `500 Internal Server Error` | Unexpected failure |

**400 vs. 422, precisely:** 400 means the HTTP request itself is broken (can't even be parsed
into the expected shape). 422 means it parsed fine but a field's *value* is invalid — bad email
format, a weak password, a negative TTL. This distinction is applied consistently so client code
can retry-with-backoff on one and never on the other.

### Error code catalog

| `code` | HTTP | Where it appears |
|---|---|---|
| `MALFORMED_REQUEST` | 400 | Any endpoint, bad JSON |
| `VALIDATION_ERROR` | 422 | Any endpoint with a request body |
| `UNAUTHENTICATED` | 401 | Any protected endpoint, missing/invalid token |
| `INVALID_CREDENTIALS` | 401 | `/auth/login` |
| `MFA_REQUIRED` | 401 | `/auth/login`, when `users.mfa_enabled` is true (see §6.1) |
| `ACCOUNT_LOCKED` | 423 | `/auth/login`, `users.locked_until` in the future |
| `ACCOUNT_DISABLED` | 403 | `/auth/login`, `users.status = 'disabled'` |
| `FORBIDDEN` | 403 | Any endpoint, policy engine deny |
| `NOT_FOUND` | 404 | Any single-resource endpoint |
| `CONFLICT` | 409 | Duplicate unique key (email, slug, role name, group name, membership) |
| `OWNER_CONFLICT` | 409 | `POST /api-keys`, the XOR-owner check constraint |
| `TOKEN_EXPIRED` | 401 | `/auth/token/refresh` |
| `TOKEN_REUSE_DETECTED` | 401 | `/auth/token/refresh`, a superseded token was replayed |
| `RATE_LIMITED` | 429 | `/auth/login` and other write-heavy endpoints |
| `INTERNAL_ERROR` | 500 | Anywhere |

## 4. Endpoint catalog

59 operations across 36 paths, grouped exactly like the OpenAPI tags:

### Auth
| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | Password login → new session + token pair |
| POST | `/auth/token/refresh` | Rotate a refresh token, reuse-detection built in |
| POST | `/auth/logout` | Revoke the current session |
| GET | `/auth/sessions` | List the caller's own active sessions |
| DELETE | `/auth/sessions` | Revoke every session for the caller ("logout everywhere") |
| DELETE | `/auth/sessions/{sessionId}` | Revoke one session (self, or another user's with `session:delete`) |

### Organizations
| Method | Path | Purpose |
|---|---|---|
| POST | `/organizations` | Create a tenant (platform-admin only) |
| GET | `/organizations/{organizationId}` | Get a tenant |
| PATCH | `/organizations/{organizationId}` | Update name/status |
| DELETE | `/organizations/{organizationId}` | Suspend/soft-delete a tenant |

### Users
| Method | Path | Purpose |
|---|---|---|
| GET | `/users` | List users in the caller's org |
| POST | `/users` | Create/invite a user |
| GET | `/users/{userId}` | Get a user |
| PATCH | `/users/{userId}` | Update a user |
| DELETE | `/users/{userId}` | Soft-delete a user |
| GET | `/users/{userId}/roles` | List direct role grants |
| POST | `/users/{userId}/roles` | Grant a role directly (supports `expires_at` for JIT access) |
| DELETE | `/users/{userId}/roles/{roleId}` | Revoke a direct grant |
| GET | `/users/{userId}/effective-permissions` | Resolve direct + group-inherited permissions |

### Groups
| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/groups` | List / create groups |
| GET / PATCH / DELETE | `/groups/{groupId}` | Read / update / delete a group |
| GET / POST | `/groups/{groupId}/members` | List / add members |
| DELETE | `/groups/{groupId}/members/{userId}` | Remove a member |
| GET / POST | `/groups/{groupId}/roles` | List / grant roles the group confers on its members |
| DELETE | `/groups/{groupId}/roles/{roleId}` | Revoke a group role grant |

### Roles
| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/roles` | List / create roles |
| GET / PATCH / DELETE | `/roles/{roleId}` | Read / update / delete a role |
| GET / POST | `/roles/{roleId}/permissions` | List / add permissions on a role |
| DELETE | `/roles/{roleId}/permissions/{permissionId}` | Remove a permission from a role |

### Permissions (read-only)
| Method | Path | Purpose |
|---|---|---|
| GET | `/permissions` | List system-defined permissions |
| GET | `/permissions/{permissionId}` | Get one |

### Service Accounts
| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/service-accounts` | List / create service accounts |
| GET / PATCH / DELETE | `/service-accounts/{serviceAccountId}` | Read / update / delete |
| GET / POST | `/service-accounts/{serviceAccountId}/roles` | List / grant roles |
| DELETE | `/service-accounts/{serviceAccountId}/roles/{roleId}` | Revoke a role |
| POST | `/service-accounts/{serviceAccountId}/token` | Exchange an API key for a short-lived JWT |

### API Keys
| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/api-keys` | List / create keys (secret shown once, on create) |
| GET / DELETE | `/api-keys/{apiKeyId}` | Read metadata / revoke |
| GET / POST | `/api-keys/{apiKeyId}/permissions` | List / add a key's own scopes |
| DELETE | `/api-keys/{apiKeyId}/permissions/{permissionId}` | Remove a scope |

### Audit Logs & Login History (both read-only)
| Method | Path | Purpose |
|---|---|---|
| GET | `/audit-logs` | Query by actor, resource, result, time range |
| GET | `/audit-logs/{auditLogId}` | Get one entry |
| GET | `/login-history` | Query login attempts by user, status, IP, time range |

## 5. Selected endpoints, in detail

The patterns below repeat across the catalog; rather than re-explain them 36 times, here are the
five that introduce something genuinely different, plus the validation/error specifics for each.

### 5.1 `POST /auth/login`

**Request**
```json
{ "email": "marcus.webb@acme.com", "password": "Tr0ub4dor&3xample!" }
```

**Response — `200 OK`**
```json
{
  "access_token": "eyJhbGciOiJFZERTQSJ9...",
  "refresh_token": "rt_9f8e7d6c5b4a...",
  "token_type": "Bearer",
  "expires_in": 900,
  "session_id": "9c1e2f3a-4b5c-6d7e-8f90-1a2b3c4d5e6f"
}
```

**Validation:** `email` — required, valid email format, max 255 chars. `password` — required,
non-empty (the *complexity* rule is enforced at signup/reset time on `UserCreate`, not re-checked
at login — a login attempt just needs *a* string to hash-compare).

**Errors specific to this endpoint:**
- `423 ACCOUNT_LOCKED` when `users.locked_until` is in the future — the body includes the unlock
  time so a client can show a countdown instead of an infinite retry loop.
- `403 ACCOUNT_DISABLED` when `users.status = 'disabled'`.
- `401 MFA_REQUIRED` when `users.mfa_enabled` is true: password was correct, but no tokens are
  issued yet. The response carries an `mfa_challenge_token` to submit to a follow-up MFA-verify
  endpoint (MFA factor storage is an explicitly deferred extension — see the schema doc's
  "known extension points" — so that endpoint is sketched, not fully specified, here).
- `429 RATE_LIMITED` after repeated failures from the same IP or against the same email, with
  `Retry-After` set — this is the brute-force control that backs `login_history`'s
  `failure_bad_password` accumulation.

Every attempt — success or failure, known email or not — writes one `login_history` row before
the response is returned, so the audit trail can't be bypassed by an error path.

### 5.2 `POST /auth/token/refresh`

**Request**
```json
{ "refresh_token": "rt_9f8e7d6c5b4a..." }
```

**Response — `200 OK`:** same shape as login's `TokenResponse`, with a **new** `refresh_token` —
the old one is immediately marked revoked with `replaced_by_token_id` pointing at the new row.

**The interesting error:** `401 TOKEN_REUSE_DETECTED`. If a client presents a refresh token whose
`replaced_by_token_id` is already set — meaning it was already exchanged once — that's the
signature of a stolen token being used alongside the legitimate one. The response still returns
`401`, but as a side effect the entire `family_id` is revoked, which cascades to killing every
session descended from that original login. The caller finds out they're logged out everywhere;
that's intentional.

### 5.3 `POST /api-keys`

**Request**
```json
{
  "name": "ci-integration-tests",
  "owner_service_account_id": "3fd2a9c1-7e4b-4f2a-9c3d-1e2f3a4b5c6d",
  "expires_at": "2026-11-01T00:00:00Z",
  "permission_ids": ["8f2e1a3b-...", "a013c9d2-..."]
}
```

**Response — `201 Created`**
```json
{
  "id": "d4e5f6a7-...",
  "organization_id": "1a2b3c4d-...",
  "owner_user_id": null,
  "owner_service_account_id": "3fd2a9c1-...",
  "name": "ci-integration-tests",
  "key_prefix": "sk_live_ex01",
  "status": "active",
  "last_used_at": null,
  "expires_at": "2026-11-01T00:00:00Z",
  "created_at": "2026-08-07T20:14:00Z",
  "revoked_at": null,
  "revoked_reason": null,
  "secret": "sk_live_<raw-secret-shown-once-only>"
}
```

`secret` appears **only in this response**. Every other endpoint that returns an `ApiKey` (list,
get) omits it entirely, because only `key_hash` is ever persisted — there is nothing to return
even if the API wanted to.

**Validation:** `name` required, 1–150 chars. Exactly one of `owner_user_id` /
`owner_service_account_id` must be present — this is checked at the application layer *before*
the insert, but it exists because `ck_api_keys_single_owner` would reject it anyway; the API
returns a clean `409 OWNER_CONFLICT` rather than surfacing a raw constraint-violation message.
`permission_ids`, if given, must each resolve to a real `permissions.id`, else `404`.

### 5.4 `POST /service-accounts/{serviceAccountId}/token`

Authenticated with `X-Api-Key`, not a bearer token — this is the one endpoint in the catalog
where the caller doesn't have a JWT yet, by definition.

**Request** (body optional)
```json
{ "requested_ttl_seconds": 900 }
```

**Response — `200 OK`**
```json
{ "access_token": "eyJhbGciOiJFZERTQSJ9...", "token_type": "Bearer", "expires_in": 900 }
```

No `refresh_token`, no `session_id` — machine callers hold their long-lived API key and just
repeat this exchange when the short-lived token expires, rather than managing a refresh chain.

**Errors:** `403` if the presented key doesn't belong to *this* `serviceAccountId` (a valid key
for a different service account is a permission error, not a 401 — the key itself authenticated
fine) or if the service account's `status` is `disabled`.

### 5.5 `GET /audit-logs`

**Request:** `GET /audit-logs?actor_type=user&resource_type=role&result=success&occurred_after=2026-07-01T00:00:00Z&limit=50`

**Response — `200 OK`**
```json
{
  "data": [
    {
      "id": "48213077",
      "organization_id": "1a2b3c4d-...",
      "actor_type": "user",
      "actor_id": "b6f1c2d3-...",
      "action": "role.assign",
      "resource_type": "user_roles",
      "resource_id": "e7f8a9b0-...:role-payments-oncall",
      "result": "success",
      "ip_address": "203.0.113.42",
      "metadata": { "role_name": "payments-oncall", "expires_at": "2026-08-07T22:00:00Z" },
      "prev_hash": "3f8a...",
      "record_hash": "9c1e...",
      "occurred_at": "2026-08-07T18:02:11Z"
    }
  ],
  "page": { "next_cursor": "eyJvIjoiMjAyNi0wOC0wN1QxODowMjoxMVoiLCJpIjoiNDgyMTMwNzcifQ", "has_more": true, "limit": 50 }
}
```

`prev_hash` / `record_hash` are exposed deliberately: an auditor (or an automated integrity job)
can walk the page sequence and recompute each `record_hash` from its row content plus the prior
row's hash, independently verifying that nothing in the exported range was altered after the
fact — the entire point of a tamper-evident log is defeated if the API hides the mechanism that
makes it checkable.

**Validation:** `occurred_after` must be `<= occurred_before` when both are given, else `400`
(a range that can never match anything is a client bug worth rejecting, not silently returning
zero rows for).

## 6. Notes on endpoints deliberately *not* built

- **No `POST /permissions`.** Permissions are seeded by the platform (see the schema doc); an API
  that let tenants invent arbitrary `resource:action` pairs would fragment the permission space
  every role-permission check has to reason about. `permissions` is read-only by design.
- **No hard-delete anywhere a soft-delete exists in the schema** (`users`, `organizations`).
  Every `DELETE` on those resources is a status flip, matching `deleted_at` / `status` columns
  that exist specifically so audit and login history rows keep a valid (if deactivated) principal
  to point at.
- **No bulk/batch endpoints.** Every list operation in this catalog is scoped to one organization
  already; cross-tenant bulk operations belong to an internal platform-admin API, not this one.
