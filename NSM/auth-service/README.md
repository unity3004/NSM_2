# auth-service

Go implementation of the Enterprise Authentication Service designed in the
sibling documents `../auth_service_schema.sql`, `../auth-service-database-schema.md`,
and `../auth-service-openapi.yaml`. This README explains *why the folders
are shaped this way* — the "how do I add a new endpoint" answer follows
directly from understanding that once.

**Status:** the Auth + Users vertical slice (`POST /auth/login`,
`POST /auth/token/refresh`, `POST /auth/logout`, and basic user CRUD) is
fully implemented end to end — real Postgres repositories, real handlers,
a passing test suite. The other nine resources in the OpenAPI spec
(Organizations, Roles, Permissions, Groups, Service Accounts, API Keys,
Audit Logs, Login History) have their `entity` types and `repository`
contracts defined and follow the *identical* pattern for
service/handler/postgres — see "Extending the slice" below.

```
go build ./... && go vet ./... && go test ./...   # all pass, right now
```

## Running locally

`docker compose up` (from `docker/`) is the whole setup — Postgres, Redis,
migrations, and the app container are wired together with the right
`depends_on`/healthcheck ordering (see `docker/docker-compose.yml`). The
one thing it needs that Docker can't generate on its own the first time is
covered automatically:

1. `docker compose -f docker/docker-compose.yml up --build` (or
   `make docker-up`) — the one-shot `keygen` service runs
   `go run ./cmd/devkeygen` for you, writing a disposable, development-only
   Ed25519 signing key to git-ignored `docker/.dev-secrets/` before `app`
   starts. Nothing to generate by hand.
2. `app` mounts that file read-only and points
   `AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH` at it (see `AUTH_ACCESS_TOKEN_KEY_ID`/
   `AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH` in `docker-compose.yml`) — `Config.Validate()`
   passes, and the server starts listening on `:8080`.
3. `POST http://localhost:8080/v1/auth/login` with a registered user's
   credentials returns a signed access token; any endpoint guarded by
   `middleware.Authenticate` (e.g. `POST /v1/auth/logout/current`) accepts
   it back — the key that signed it is the same one `LoadSigningKeySet`
   loaded in step 2.

Running `cmd/server` directly instead of through Compose needs the same
key by hand: `go run ./cmd/devkeygen` writes the identical file, then copy
`configs/.env.example` to `configs/.env` (or export the two
`AUTH_ACCESS_TOKEN_*` variables it documents) before `go run ./cmd/server`.

The key this produces is Ed25519, PKCS#8 PEM, generated fresh by
`crypto/rand` — **never a production key, never committed** (`docker/.dev-secrets/`
is in `.gitignore`), and never logged (`internal/config/log_value.go`
redacts `access_token.private_key_pem`; `private_key_path` is just a
filesystem path, not key material).

## Why Clean Architecture, and what that means here

The rule that matters is: **dependencies point inward, and inner layers
know nothing about outer ones.** Concretely, in this repo:

```
entity  ←  repository (interfaces only)  ←  service  ←  handler/http
  ↑                                                          ↑
  └──────────────── dto (shapes only, no logic) ─────────────┘

repository/postgres  implements the repository interfaces (an outer detail)
database, middleware, config, util  are infrastructure every layer may use
```

`internal/entity` imports nothing of ours. `internal/service` imports
`entity` and `repository` (an interface), never `repository/postgres`
directly — `cmd/server/main.go` is the only place a concrete
`postgres.userRepository` and an abstract `service.AuthService` ever meet.
That single wiring point is what lets `internal/service/auth_service_test.go`
run real business logic — lockout thresholds, refresh-token rotation,
reuse detection — against the hand-written fakes in
`internal/repository/mocks`, with no database, in under four seconds.

## Folder-by-folder

### `cmd/server`
The one `main()` in this repository. It does nothing but read config,
open a database connection, construct each repository → service → handler
in dependency order, and start an `http.Server` with graceful shutdown.
**Why a separate `cmd/`:** a second binary — a migration runner, a
one-off backfill script — gets its own `cmd/whatever/main.go` without
duplicating any wiring logic, because none of the real logic lives here.

### `internal/entity` — Entities
The domain objects: `User`, `Organization`, `Role`, `Session`,
`RefreshToken`, `APIKey`, and so on, one file per zone of the schema
(mirroring the ERD's Identity / RBAC / Credentials / Sessions / Audit
groupings). Also `errors.go` — the sentinel errors (`ErrNotFound`,
`ErrTokenReuseDetected`, ...) that flow, unchanged, from a repository
method all the way to the HTTP response. **Why entities are `internal/`
and dependency-free:** this is the layer everything else is judged
against; the moment it imports `database/sql` or `net/http`, "swap the
database" or "add gRPC" stop being one-file changes.

### `internal/dto` — DTOs
The HTTP wire format: `LoginRequest`, `TokenResponse`, `UserCreateRequest`,
one file per resource group, matching `auth-service-openapi.yaml`'s
schemas field-for-field. Each request DTO carries its own `Validate()`
method (the same rules as the spec — email format, password complexity,
XOR ownership on API keys) and a `ToEntity()`/`...FromEntity()` mapper.
**Why DTOs are a separate layer from entities, not the same struct reused:**
a column can be renamed without touching the public API, and the JSON
shape can evolve (add a field, change a name) without touching business
logic — the mapping functions are the only code that has to know both
shapes at once.

### `internal/repository` — Repositories (interfaces)
The **ports**: `UserRepository`, `SessionRepository`, `RoleRepository`, and
so on — interfaces only, no SQL, no `database/sql` import. `internal/service`
depends on these, never on a concrete implementation.
**Why the interface lives here and not next to its Postgres implementation:**
so `internal/service` can be compiled, and unit-tested, without
`internal/repository/postgres` existing at all — which is exactly what
`auth_service_test.go` does.

### `internal/repository/postgres` — Repositories (implementation)
The **adapters**: real `database/sql` queries implementing the interfaces
above, one file per aggregate (`user_repository.go`, `session_repository.go`,
...), plus `db.go` (shared null-handling helpers) and `errors.go`
(translating a Postgres unique-violation into `entity.ErrAlreadyExists`
once, instead of in every method). `refresh_token_repository.go`'s
`Rotate` is the one method worth reading closely: it revokes the old token
and inserts the new one inside a single transaction, because a crash
between the two must never leave a token that's simultaneously "valid" and
"already replaced" — that ambiguity is what reuse detection depends on
being impossible.

### `internal/repository/mocks` — test doubles
Hand-written in-memory fakes for the same interfaces, no mocking
framework. They exist so `internal/service`'s tests exercise real control
flow (five wrong passwords → locked; a rotated-then-replayed refresh token
→ family revoked) in milliseconds. This is not `test/` because it's
production code in the sense that matters: it ships in the module and
`internal/service`'s tests import it directly.

### `internal/service` — Services (use cases)
The business logic: `AuthService` (login, refresh, logout — see
`auth_service.go`'s doc comments for the lockout and rotation rules) and
`UserService`. Depends only on `repository` interfaces, `entity`, and
`util`. **Why this is where password hashing happens, not in the
handler or the repository:** hashing is a business rule ("passwords are
never stored in plaintext"), not a transport concern or a storage detail —
it belongs in the layer that owns business rules.

### `internal/handler/http` — Handlers
Translates one HTTP request into one service call and one service result
into one JSON response — `router.go` (route table), `auth_handler.go`,
`user_handler.go`, and `response.go` (the single function,
`writeServiceError`, that maps every `entity.Err*` to the exact HTTP status
+ error code the OpenAPI spec promises). **Why it's `handler/http`
specifically, not just `handler`:** a gRPC delivery mechanism would be
`handler/grpc`, calling the exact same `service.AuthService` — the
directory structure states the Clean Architecture claim ("delivery is
swappable") as a fact about the filesystem, not just a slide.

### `internal/logging` — Structured logging
`New()` builds the service's one [Zap](https://github.com/uber-go/zap)
`*zap.Logger` (JSON in every real deployment, colorized console only for a
developer's terminal); `context.go`'s `WithContext`/`FromContext` are how
a correlation ID, attached once by `middleware.RequestID`, ends up on
every subsequent log line without any function signature in the service
threading a `requestID string` through it. See "Structured logging: levels,
correlation IDs, JSON" below for the full design — this section is the
one-paragraph summary of it.

### `internal/middleware` — Middleware
Cross-cutting HTTP concerns with no business content: `RequestID` (mints
or trusts a correlation ID, derives the per-request logger from it — see
`internal/logging` above — and puts both on the request context),
`Recover` (panic → 500 + an Error-level log with the real stack trace,
never a dropped connection), `Logging` (one `http_request` line per
request), `Auth` (JWT verification → `Claims` on the request context),
`CORS`. **Why these aren't in `handler/http`:** a handler file should be
readable as "what does this endpoint do," not interleaved with "and also,
here's how auth headers get parsed" — that's a different concern with a
different rate of change.

### `internal/config` — Configuration
`Load()` builds a [Viper](https://github.com/spf13/viper) instance,
applies defaults for every non-secret field, optionally reads
`configs/config.yaml`, binds `AUTH_`-prefixed environment variables
(`AUTH_JWT_SIGNING_KEY`, `AUTH_DATABASE_HOST`, ...) over top, unmarshals
into a typed, nested `Config` struct, and fails closed if the result is
invalid — a JWT signing key under 32 characters, a missing database
password outside `development`, are startup errors, not warnings.
Precedence, highest first: **environment variables → `configs/config.yaml`
→ code defaults**. `Config` implements `zapcore.ObjectMarshaler` so
`cmd/server/main.go` can log the fully-resolved config at boot (genuinely
useful for "why is this instance pointed at the wrong database") with
secrets redacted rather than printed.
**Why code, not data:** this package is *how* to load and validate
settings; the actual per-environment values are data (see `configs/`
below) — conflating the two means either committing secrets next to
source or hiding validation logic inside a YAML file. See "Why
configuration is not hardcoded" below for the fuller argument.

### `internal/database` — Database
`NewPostgresPool(ctx, config.DatabaseConfig)` (connection, pool sizing, a
startup ping so a bad DSN fails at boot, not on the first request) and
`WithTx` (a transaction helper any two repository calls can share). Pool
size and timeouts come from the `DatabaseConfig` argument, not constants
in this file — a single local Postgres and twenty production replicas
sharing one `max_connections` budget need different numbers, and only the
deployment's configuration knows which applies. **Why this is separate
from `internal/repository/postgres`:** those files know one table's SQL
each; this file knows nothing about tables at all, only about
connections — it's the thing a *different* SQL package would still need
unchanged.

### `internal/util` — Utilities
Small, dependency-light, cross-layer helpers: `password.go` (bcrypt),
`jwt.go` (a hand-rolled HS256 signer/verifier — see its doc comment for why
that's a deliberate minimal choice, not a missed dependency), `token.go`
(opaque session/refresh secrets + their hashes), `uuid.go`, `cursor.go`
(opaque pagination cursors). **Why these exist instead of a bigger
dependency:** every one of them is 15–100 lines of standard-library code;
pulling in a JWT library or a UUID library for this would trade a small
amount of code for a dependency-update obligation forever.

### `migrations`
17 sequential `NNNNNN_description.up.sql` / `.down.sql` pairs, generated
directly from `../auth_service_schema.sql` — genuinely the same DDL, split
at table boundaries, not re-authored. **Why migrations are a top-level
folder, not inside `internal/database`:** a migration tool
(`golang-migrate`, in `docker-compose.yml`'s `migrate` service) runs
against this directory directly, with no Go compiler involved — it isn't
Go code and shouldn't live inside a Go package.

### `docker`
`Dockerfile` (multi-stage: a `golang:1.26-alpine` build stage, a
`distroless/static` runtime stage with no shell — nothing for an attacker
who reaches code execution to pivot with) and `docker-compose.yml` (app +
Postgres + Redis + a one-shot `migrate` service + a one-shot `keygen`
service, for `make docker-up`). `keygen` runs `cmd/devkeygen` against the
Dockerfile's own Go-toolchain build stage to generate a disposable,
development-only Ed25519 access-token signing key into git-ignored
`docker/.dev-secrets/` before `app` starts — see `cmd/devkeygen`'s own doc
comment and `configs/.env.example` for the equivalent outside Docker. The
`.dockerignore` that matters lives at the repo root (Docker resolves it
against the build context, not the Dockerfile's own directory).

### `.github/workflows`
`ci.yml`: lint (`golangci-lint`), a dependency vulnerability scan
(`govulncheck`), unit + integration tests against real `postgres:16-alpine`
and `redis:7.4-alpine` service containers, and a Docker build — in that
order, so a build never runs against code that failed lint or tests. The
build job only builds the image (`push: false`); it never starts the
container, so CI never needs an access-token signing key the way
`docker compose up` does.

### `test`
Everything that is *not* a colocated `_test.go` unit test:
`test/integration` (build-tagged `integration`, needs `DATABASE_URL`, proves
the SQL in `internal/repository/postgres` is correct against a real
database), `test/e2e` (currently a README explaining what would justify
adding one), and `test/fixtures` (seed SQL for integration tests). Unit
tests themselves are colocated with the code they test
(`internal/service/auth_service_test.go`) — that's idiomatic Go, not an
oversight; only cross-cutting, environment-dependent tests get their own
top-level home.

### `configs`
`config.yaml` (non-secret operational defaults — timeouts, pool sizes, log
format — safe to commit) and `.env.example` (a template for the secrets
`internal/config` requires: `AUTH_JWT_SIGNING_KEY`, `AUTH_DATABASE_PASSWORD`,
and the access-token signing key `AUTH_ACCESS_TOKEN_KEY_ID`/
`AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH` — see `cmd/devkeygen` for how to
generate a disposable development one). Deliberately separate from
`internal/config`'s *code*. Real `.env` files are gitignored; this is what
a new contributor copies.

### `api`
Points at the canonical `auth-service-openapi.yaml` one level up and
explains what changes in a standalone repo (see `api/README.md`) — kept
thin on purpose rather than duplicating a spec that already exists.

## Why configuration is not hardcoded

Every value in `internal/config.Config` was, at some point while writing
this service, a candidate for just being a constant. Here's what each one
would have cost if it had stayed that way:

- **The same binary can't run in two environments.** `database.host` as a
  constant means the binary built for staging cannot run against
  production — or `local` — without a rebuild. With `Load()`, `docker
  compose up` (local), `ci.yml`'s test job (a GitHub Actions service
  container), and a real production deployment run the *identical*
  compiled artifact from `docker/Dockerfile`; only the environment differs.
  That's the actual meaning of "build once, deploy everywhere" — it's a
  property of where configuration lives, not of the build step.

- **Rotating a secret becomes a redeploy, not a config change.** If
  `jwt.signing_key` were `const signingKey = "..."`, rotating it after a
  suspected leak means editing source, opening a PR, waiting for CI, and
  redeploying — during which the compromised key is still valid. As an
  environment variable, rotation is "update the secret in the deployment
  platform and restart the pods" — no code change, no review cycle, no
  window where fixing the leak is blocked on the same pipeline that might
  have caused it.

- **Secrets in source become secrets in git history forever.** A
  hardcoded `database.password` doesn't stop being a leak once you remove
  it in a later commit — `git log -p` still has it, and so does every
  fork and clone made in between. `Config.Validate` *requires*
  `AUTH_DATABASE_PASSWORD` to be absent from every file this repository
  tracks; the only place it can legally exist is the deployment
  platform's secret store.

- **You cannot safely log or debug what you can't separate from code.**
  `Config.LogValue` (`internal/config/log_value.go`) redacts
  `database.password` and `jwt.signing_key` before anything touches
  stdout. That's only possible because they're *data flowing through* a
  struct, not string literals baked into call sites throughout the
  codebase with no single point of redaction.

- **Tests need different values than production, at the same time.**
  `internal/service/auth_service_test.go` runs with a throwaway 15-minute
  access-token TTL and an in-memory fake; `internal/config/config_test.go`
  asserts that `AUTH_ENVIRONMENT=production` *without* a database password
  fails to start. Neither is expressible if the values under test are
  compiled into the binary the test is exercising — you'd need a
  different binary per test case.

- **A magic number hides the decision behind it.** `db.SetMaxOpenConns(25)`
  as a bare literal in `internal/database/postgres.go` looks like a fact;
  `cfg.Database.MaxOpenConns` looks like what it is — a tuning decision
  that depends on how many replicas share one Postgres instance's
  `max_connections`, which is an operational question, not a compile-time
  one. The moment it's a config field, changing it is a one-line diff in
  `configs/config.yaml` instead of a hunt through the codebase for every
  place someone typed `25`.

None of this is specific to Go or to this service — it's the same reason
the [12-Factor App](https://12factor.net/config) methodology treats
config-via-environment as a first-class rule rather than a style
preference: **the number of things that change between "it works on my
machine" and "it works in production" should be config, and only config.**

## Structured logging: levels, correlation IDs, JSON

`internal/logging` + `middleware.RequestID` + the log calls scattered
through `internal/service` and `internal/handler/http` are one design,
not three unrelated features. Each piece exists because of a real
limitation the others don't cover.

### Log levels are a filter, not a decoration

Every log call in this service picked its level by asking one question:
**who needs to see this, and how urgently?**

| Level | Used for | Example in this codebase |
|---|---|---|
| `Debug` | Detail nobody needs *until* they're debugging one specific request | `auth_service.go`: one wrong password (the count matters more than any single attempt) |
| `Info` | Normal operation, worth a permanent record but not an alert | Server started, `login succeeded`, `logout`, every non-5xx `http_request` |
| `Warn` | The code handled something correctly, but a human should probably know it happened | `account locked after repeated failed logins`, `refresh token reuse detected` — both are the system working *as designed* against a possible attack, not a bug |
| `Error` | Something failed that shouldn't have, or the response a caller got was worse than the request deserved | `unmapped service error` (a 500 with no mapped cause), a panic in `middleware.Recover` |
| `Fatal`/`Panic` (Zap) | Unrecoverable startup failure | Not used past `cmd/server/main.go`'s bootstrap phase — an unrecoverable condition in a running server should degrade a request (an `Error` + a 5xx), never `os.Exit` the whole process out from under every *other* in-flight request |

The `Warn` row is the one worth pausing on: **a caught attack and a code
defect are different things**, and conflating them at the same log level
either desensitizes whoever's paging on `Error` (real bugs get lost in
security-event noise) or under-reacts to the security event (it looks
like routine noise, not a defect, so nobody treats it as urgent). Keeping
"the system worked correctly against something hostile" at `Warn` and "the
system itself is broken" at `Error` is what lets each be alerted on
separately, correctly.

In production, the level is `AUTH_LOG_LEVEL` (default `info`) — `Debug` is
enabled per-deployment when actively investigating something, not left on
by default generating a log line for every bcrypt comparison.

### Correlation IDs: attach once, read everywhere

A single login attempt touches `middleware.RequestID` → `authHandler.login`
→ `AuthService.Login` → three repository calls → `issueSession` → two more
repository calls. Without a correlation ID, finding every log line one
request produced means guessing at a time window and hoping nothing else
was happening concurrently. With one, it's `grep request_id=req_01J...`
across the whole log stream — one request, all its lines, in order,
however many layers deep it went.

The mechanism (see `middleware/request_id.go` and `internal/logging/context.go`
in full):

```
inbound request
  → RequestID middleware: mint or trust an ID, derive
    requestLogger := baseLogger.With(zap.String("request_id", id)),
    put requestLogger on the request context
  → every layer below calls logging.FromContext(ctx) instead of holding
    its own logger reference
  → every log line any of them emit already carries request_id —
    zap.Field attached once, inherited by every log call the derived
    logger ever makes
```

The payoff: `internal/service/auth_service.go` — three layers removed from
the HTTP request — never imports `net/http`, never sees a request ID
explicitly, and its logs still carry one. That's only possible because
the correlation ID rides on `context.Context`, which every one of those
function signatures already threads through for cancellation — no new
parameter, no interface anyone had to remember to pass.

The same ID also comes back to the *caller* — `RequestID` sets the
`X-Request-Id` response header, and `dto.ErrorBody.RequestID` puts it in
every error envelope's body — so "here's the request ID from the error I
got" is a real, actionable thing a support ticket can contain, and it's
the literal string to `grep` for.

### Structured JSON, not formatted strings

Compare:

```go
// Don't: information is now trapped inside a string.
logger.Info(fmt.Sprintf("user %s locked after %d attempts", userID, attempts))

// Do: information is a field — queryable, aggregable, typed.
logger.Warn("account locked after repeated failed logins",
    zap.String("user_id", userID), zap.Int("attempts", attempts))
```

The second produces:

```json
{"level":"warn","timestamp":"2026-08-09T21:14:03.112Z","message":"account locked after repeated failed logins","service":"auth-service","environment":"production","request_id":"req_01J9X...","user_id":"3fd2a9c1-...","attempts":5,"locked_until":"2026-08-09T21:29:03.112Z"}
```

Every field on that line is something a log aggregator (Datadog, Loki,
OpenSearch — the SIEM-integration point the PRD this service traces back
to calls for explicitly) can filter, group, or alert on directly:
`attempts > 3`, `service:"auth-service"`, `level:"warn"`. The `Sprintf`
version is a string an aggregator can full-text search and nothing more —
"how many accounts got locked in the last hour" requires a regex against
free text instead of `count() by user_id where message="account locked..."`.

`service` and `environment` (attached once, in `logging.New`, via
`zap.Fields`) answer "whose logs am I even looking at" the same way
`request_id` answers "which request" — both exist so a shared log stream
from every replica of every service stays sortable into the slice anyone
actually needs.

## Extending the slice

To bring, say, Roles up to the same level as Users:

1. `internal/entity/rbac.go` already has `Role` and `RolePermission` — done.
2. `internal/repository/rbac.go` already declares `RoleRepository` — done.
3. Add `internal/repository/postgres/role_repository.go` implementing it —
   copy `user_repository.go`'s shape (a `dbtx`-backed struct, a
   `scanRole` helper, `translateError` on every write).
4. Add `internal/service/rbac_service.go` — a thin wrapper, same shape as
   `user_service.go`.
5. Add `internal/handler/http/role_handler.go` and register its routes in
   `router.go`.
6. Wire the new repository/service into `cmd/server/main.go`.

No existing file changes in step 3–6 beyond `router.go`'s route table and
`main.go`'s wiring block — that's the dependency rule paying for itself.
