-- Drop enum types. Safe only once every table using them is gone —
-- i.e. only when rolling back the entire migration history in order.
DROP TYPE IF EXISTS audit_result;
DROP TYPE IF EXISTS audit_actor_type;
DROP TYPE IF EXISTS auth_method;
DROP TYPE IF EXISTS login_status;
DROP TYPE IF EXISTS token_revocation_reason;
DROP TYPE IF EXISTS api_key_status;
DROP TYPE IF EXISTS service_account_status;
DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS org_status;
