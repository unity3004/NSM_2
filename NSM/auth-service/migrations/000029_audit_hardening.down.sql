DROP TRIGGER IF EXISTS audit_logs_immutable ON audit_logs;
DROP FUNCTION IF EXISTS reject_audit_log_mutation();
DROP INDEX IF EXISTS idx_audit_logs_request_id;
DROP INDEX IF EXISTS idx_audit_logs_action;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS request_id;
