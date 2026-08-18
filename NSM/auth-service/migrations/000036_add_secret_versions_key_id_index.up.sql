-- Re-encryption engine (service.ReEncryptionService) queries
-- secret_versions WHERE key_id = $1 repeatedly — once per batch, for the
-- entire duration of a migration. CountVersionsByKeyID
-- (migrations/000026) already runs this exact shape of query too, just
-- once per RetireKey call rather than in a tight loop; neither had an
-- index to use before this migration. Not partial (unlike
-- idx_secrets_active) — every row's key_id is queried by this pattern
-- regardless of deleted_at, so a partial index would not help here the
-- way it does for that other, deleted_at-filtered query shape.
CREATE INDEX idx_secret_versions_key_id ON secret_versions (key_id);
