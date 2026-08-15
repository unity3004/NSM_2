package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lib/pq"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

// secretPolicyRepository implements repository.SecretPolicyRepository —
// see migrations/000027_create_secret_policies's own doc comment for the
// schema.
type secretPolicyRepository struct{ db *sql.DB }

func NewSecretPolicyRepository(db *sql.DB) repository.SecretPolicyRepository {
	return &secretPolicyRepository{db: db}
}

const secretPolicyColumns = `id, organization_id, name, description, created_at, updated_at`

func scanSecretPolicy(row interface{ Scan(dest ...any) error }) (*entity.SecretPolicy, error) {
	var p entity.SecretPolicy
	var orgID, description sql.NullString
	err := row.Scan(&p.ID, &orgID, &p.Name, &description, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.OrganizationID = nullString(orgID)
	p.Description = nullString(description)
	return &p, nil
}

func (r *secretPolicyRepository) Create(ctx context.Context, p *entity.SecretPolicy) error {
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO secret_policies (organization_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`,
		toNullString(p.OrganizationID), p.Name, toNullString(p.Description),
	).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt)
	return translateError(err)
}

func (r *secretPolicyRepository) GetByID(ctx context.Context, id string) (*entity.SecretPolicy, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+secretPolicyColumns+` FROM secret_policies WHERE id = $1`, id)
	return scanSecretPolicy(row)
}

// List returns organizationID's own tenant-defined policies plus every
// platform-wide policy — the identical "organization_id = $1 OR
// organization_id IS NULL" shape roleRepository.List already uses for the
// same reason (see entity.SecretPolicy's own doc comment).
func (r *secretPolicyRepository) List(ctx context.Context, organizationID string) ([]*entity.SecretPolicy, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+secretPolicyColumns+` FROM secret_policies
		 WHERE organization_id = $1 OR organization_id IS NULL
		 ORDER BY organization_id NULLS FIRST, name ASC`,
		organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*entity.SecretPolicy
	for rows.Next() {
		p, err := scanSecretPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

func (r *secretPolicyRepository) Update(ctx context.Context, p *entity.SecretPolicy) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE secret_policies SET name = $1, description = $2, updated_at = now() WHERE id = $3`,
		p.Name, toNullString(p.Description), p.ID)
	return checkRowsAffected(res, err)
}

func (r *secretPolicyRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM secret_policies WHERE id = $1`, id)
	return checkRowsAffected(res, err)
}

// ReplaceRules swaps policyID's entire rule set inside one transaction —
// delete every existing rule (cascading to secret_policy_rule_actions),
// then insert rules fresh. There is no in-place "diff the old set against
// the new one" logic: this is deliberately the simplest correct semantics
// (see the interface's own doc comment), and it keeps this method's SQL
// straightforward enough to read in one pass.
func (r *secretPolicyRepository) ReplaceRules(ctx context.Context, policyID string, rules []*entity.SecretPolicyRule) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after a successful Commit

	if _, err := tx.ExecContext(ctx, `DELETE FROM secret_policy_rules WHERE policy_id = $1`, policyID); err != nil {
		return err
	}

	for _, rule := range rules {
		var ruleID string
		err := tx.QueryRowContext(ctx, `
			INSERT INTO secret_policy_rules (policy_id, path_pattern, effect)
			VALUES ($1, $2, $3)
			RETURNING id`,
			policyID, rule.PathPattern, string(rule.Effect),
		).Scan(&ruleID)
		if err != nil {
			return translateError(err)
		}
		for _, action := range rule.Actions {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO secret_policy_rule_actions (rule_id, action) VALUES ($1, $2)`,
				ruleID, string(action),
			); err != nil {
				return translateError(err)
			}
		}
	}

	return tx.Commit()
}

func (r *secretPolicyRepository) ListRules(ctx context.Context, policyID string) ([]*entity.SecretPolicyRule, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, policy_id, path_pattern, effect, created_at FROM secret_policy_rules WHERE policy_id = $1 ORDER BY created_at ASC`,
		policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*entity.SecretPolicyRule
	for rows.Next() {
		var rule entity.SecretPolicyRule
		var effect string
		if err := rows.Scan(&rule.ID, &rule.PolicyID, &rule.PathPattern, &effect, &rule.CreatedAt); err != nil {
			return nil, err
		}
		rule.Effect = entity.PolicyEffect(effect)
		rules = append(rules, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := r.attachActions(ctx, rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// attachActions bulk-fetches every action for the given rules (one query,
// not one per rule) and populates each rule's Actions field in place.
func (r *secretPolicyRepository) attachActions(ctx context.Context, rules []*entity.SecretPolicyRule) error {
	if len(rules) == 0 {
		return nil
	}
	ruleIDs := make([]string, len(rules))
	byID := make(map[string]*entity.SecretPolicyRule, len(rules))
	for i, rule := range rules {
		ruleIDs[i] = rule.ID
		byID[rule.ID] = rule
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT rule_id, action FROM secret_policy_rule_actions WHERE rule_id = ANY($1)`,
		pq.Array(ruleIDs))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var ruleID, action string
		if err := rows.Scan(&ruleID, &action); err != nil {
			return err
		}
		if rule, ok := byID[ruleID]; ok {
			rule.Actions = append(rule.Actions, entity.PolicyAction(action))
		}
	}
	return rows.Err()
}

func (r *secretPolicyRepository) AssignToRole(ctx context.Context, a *entity.SecretPolicyRoleAssignment) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO secret_policy_role_assignments (policy_id, role_id, assigned_by)
		VALUES ($1, $2, $3)`,
		a.PolicyID, a.RoleID, toNullString(a.AssignedBy))
	return translateError(err)
}

func (r *secretPolicyRepository) UnassignFromRole(ctx context.Context, policyID, roleID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM secret_policy_role_assignments WHERE policy_id = $1 AND role_id = $2`,
		policyID, roleID)
	return checkRowsAffected(res, err)
}

func (r *secretPolicyRepository) ListAssignedRoleIDs(ctx context.Context, policyID string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT role_id FROM secret_policy_role_assignments WHERE policy_id = $1`, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ListRulesForRoles is the PolicyEvaluator's entire data-access footprint
// for one authorization decision — see the interface's own doc comment.
// One query for the rules (joining role assignment + organization
// visibility), then attachActions' one bulk query for their actions: two
// round trips total, never N.
func (r *secretPolicyRepository) ListRulesForRoles(ctx context.Context, organizationID string, roleIDs []string) ([]*entity.SecretPolicyRule, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT spr.id, spr.policy_id, spr.path_pattern, spr.effect, spr.created_at
		FROM secret_policy_rules spr
		JOIN secret_policies sp ON sp.id = spr.policy_id
		JOIN secret_policy_role_assignments spra ON spra.policy_id = sp.id
		WHERE spra.role_id = ANY($1)
		  AND (sp.organization_id = $2 OR sp.organization_id IS NULL)`,
		pq.Array(roleIDs), organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*entity.SecretPolicyRule
	for rows.Next() {
		var rule entity.SecretPolicyRule
		var effect string
		if err := rows.Scan(&rule.ID, &rule.PolicyID, &rule.PathPattern, &effect, &rule.CreatedAt); err != nil {
			return nil, err
		}
		rule.Effect = entity.PolicyEffect(effect)
		rules = append(rules, &rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := r.attachActions(ctx, rules); err != nil {
		return nil, err
	}
	return rules, nil
}
