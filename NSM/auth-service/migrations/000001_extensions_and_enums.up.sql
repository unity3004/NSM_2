-- ============================================================================
-- Enterprise Authentication Service — Database Schema
-- Dialect: PostgreSQL 15+
-- Normal form: 3NF (see auth-service-database-schema.md for justification)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;   -- case-insensitive email column
