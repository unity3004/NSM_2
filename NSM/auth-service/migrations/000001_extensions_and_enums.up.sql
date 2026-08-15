-- ============================================================================
-- Enterprise Authentication Service — Database Schema
-- Dialect: PostgreSQL 15+
-- Normal form: 3NF (see auth-service-database-schema.md for justification)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;   -- case-insensitive email column

-- Enum types every later migration's tables reference. Values must stay in
-- exact sync with their Go mirror (see the doc comment naming each one
-- below) — a mismatch here is not caught at compile time, only at the
-- first INSERT/UPDATE that tries to use the missing value.
CREATE TYPE org_status              AS ENUM ('active', 'suspended', 'deleted');                                                                  -- entity.OrgStatus
CREATE TYPE user_status             AS ENUM ('active', 'disabled', 'locked', 'pending_verification');                                            -- entity.UserStatus
CREATE TYPE service_account_status  AS ENUM ('active', 'disabled');                                                                               -- entity.ServiceAccountStatus
CREATE TYPE api_key_status          AS ENUM ('active', 'revoked', 'expired');                                                                     -- entity.APIKeyStatus
CREATE TYPE token_revocation_reason AS ENUM ('logout', 'rotation', 'reuse_detected', 'admin_revoked', 'expired', 'password_reset', 'breakglass'); -- entity.RevocationReason
CREATE TYPE login_status            AS ENUM ('success', 'failure_bad_password', 'failure_mfa', 'failure_locked', 'failure_disabled', 'failure_unknown_identity', 'failure_other'); -- entity.LoginStatus
CREATE TYPE auth_method             AS ENUM ('password', 'sso_oidc', 'sso_saml', 'api_key', 'service_account_token', 'webauthn');                 -- entity.AuthMethod
CREATE TYPE audit_actor_type        AS ENUM ('user', 'service_account', 'api_key', 'system');                                                     -- entity.AuditActorType
CREATE TYPE audit_result            AS ENUM ('success', 'failure', 'denied');                                                                     -- entity.AuditResult
