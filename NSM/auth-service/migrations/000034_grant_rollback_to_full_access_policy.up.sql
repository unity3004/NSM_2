-- Backward compatibility for the migration 000027 "Full Access (system
-- default)" policy, the same reasoning that migration itself already
-- documents: every role holding it before this migration must keep the
-- exact same effective access afterward, now including rollback (which
-- did not exist as a distinct grantable action until 000033). Without
-- this, adding "rollback" as a policy action would silently revoke
-- rollback from every role that currently has it purely through this
-- policy plus secrets:rollback (migrations/000032) — the identical
-- "close the gap or existing access silently narrows" concern 000027's
-- own migration addressed for the original five actions.
INSERT INTO secret_policy_rule_actions (rule_id, action)
VALUES ('00000000-0000-4000-9000-000000000201', 'rollback')
ON CONFLICT DO NOTHING;
