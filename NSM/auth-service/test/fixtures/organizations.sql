-- Fixture data for test/integration. Applied manually or by a test's
-- setup step against a freshly migrated database — never part of the
-- migrations/ directory itself, since fixtures are test data, not schema.
INSERT INTO organizations (id, name, slug, status)
VALUES ('00000000-0000-4000-8000-000000000001', 'Fixture Org', 'fixture-org', 'active')
ON CONFLICT (id) DO NOTHING;
