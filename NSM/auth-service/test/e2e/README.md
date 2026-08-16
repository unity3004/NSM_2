# End-to-end tests

Black-box HTTP tests against a fully running binary — `docker compose up`
(see `../../docker/docker-compose.yml`), then real requests over the
network to `http://localhost:8080`, asserting on the JSON responses
exactly as `auth-service-openapi.yaml` documents them.

This is deliberately empty in the scaffold: e2e tests are expensive to run
and maintain, and the two layers above already cover the two things that
actually break —

- `internal/service/*_test.go` (colocated unit tests) prove the business
  logic is correct against fakes.
- `test/integration/` proves the SQL in `internal/repository/postgres` is
  correct against a real Postgres.

Add a suite here once there's a second real consumer of the API (a CLI, a
frontend) whose integration with the *whole* running stack — including
`docker/Dockerfile`'s build, not just the Go code — is worth pinning down.
Structure it the same way as `test/integration`: a build tag (`e2e`), a
`DATABASE_URL`/`BASE_URL`-style environment-variable skip guard, and a CI
job that brings up `docker-compose.yml` before running it.
