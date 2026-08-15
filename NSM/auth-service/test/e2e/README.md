# End-to-end tests

Black-box HTTP tests: an `*http.Client` talking to an `httptest.Server`
wrapping the exact `http.Handler` `httphandler.NewRouter` builds for
`cmd/server/main.go` — the real router, the real middleware chain, the real
handlers and services — against real PostgreSQL and, when rate limiting is
enabled (the production default), real Redis. No handler, service, or
repository is ever called directly from a test in this package; every
assertion is made against an HTTP response.

Gated behind the `e2e` build tag, the same way `test/integration` is gated
behind `integration` — `go test ./...` never runs or compiles this package.

## Running

1. Bring up Postgres (and Redis, unless you set `AUTH_RATE_LIMIT_ENABLED=false`)
   and apply migrations — `docker compose -f docker/docker-compose.yml up`
   from the repo root does all of it, including generating a local Ed25519
   signing key (see that file's `keygen` service).
2. Export the same `AUTH_*` variables `docker-compose.yml`'s `app` service
   and `configs/.env.example` already document — `AUTH_JWT_SIGNING_KEY`,
   `AUTH_DATABASE_URL` (or the component `AUTH_DATABASE_*` fields, which
   default to the docker-compose Postgres), `AUTH_ACCESS_TOKEN_KEY_ID`,
   `AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH`. If you're running against
   docker-compose from the host rather than from inside its network, unset
   or override `AUTH_REDIS_ADDR`/`AUTH_DATABASE_URL` to point at `localhost`
   rather than the `redis`/`postgres` service names.
3. Run:

   ```
   go test -tags=e2e ./test/e2e/...
   ```

`AUTH_JWT_SIGNING_KEY` is this suite's one skip guard — unset, every test
in this package reports `SKIP` with instructions on what to set. Once it's
set, every other problem (bad config, unreachable Postgres, unreachable
Redis while `rate_limit.enabled` is true, a missing signing-key file) is a
hard `t.Fatalf`, never a silent skip: setting that variable is this suite's
signal that the environment intends to actually run it.

## What's covered

`registration_login_protected_test.go` — **Sprint 2 E2E Scenario #1:
Registration → Login → Protected API**:

- `POST /v1/auth/register` persists a real Argon2id hash in PostgreSQL
  (verified both by decoding the stored `password_hash` and by running it
  back through the real `security.PasswordService.Verify`) and returns no
  password, hash, or key material.
- `POST /v1/auth/login` authenticates against that real hash and returns a
  real access token, which is decoded and verified with the real
  `util.JWTSigner.Verify` (the exact code `middleware.Auth` runs on every
  protected request) — subject, organization, session, and expiry claims
  are all checked, and a signature-tampered copy of the same token is
  confirmed to fail verification.
- `GET /v1/users/{userId}` accepts that access token when it carries a
  valid `Authorization: Bearer` header, proving `middleware.Auth` is
  actually wired into the router (not just unit-tested in isolation) —
  and rejects the same request with no token, a malformed token, and a
  token with a tampered signature, in each case with `401` and no leaked
  data.

## What isn't (yet)

Everything else in `auth-service-openapi.yaml` — refresh, logout, MFA,
RBAC, service accounts, the Milestone 5A/6B `security.TokenService`-backed
routes (`POST /v1/auth/refresh`, `POST /v1/auth/logout/current`), rate-limit
enforcement itself. Add a suite here per scenario, following this file's
structure (`setup_test.go`'s `newE2EEnv` is reusable as-is).
