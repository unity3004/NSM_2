-- Registration (Milestone 3) needs Postgres UNIQUE as the final protection
-- against duplicate usernames, the same way uq_users_org_email already
-- protects duplicate emails (000003_create_users_table.up.sql) — that
-- constraint was never added for username because nothing before this
-- milestone created users by username. NULL-safe: Postgres treats every
-- NULL as distinct in a UNIQUE index, so SSO/invited accounts with no
-- username never collide with each other or with a registered one.
ALTER TABLE users ADD CONSTRAINT uq_users_org_username UNIQUE (organization_id, username);
