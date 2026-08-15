package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// SecretPolicyRepository persists entity.SecretPolicy, its rules, and
// which roles it's assigned to — see migrations/000027's own doc comment
// for the schema this implements.
type SecretPolicyRepository interface {
	Create(ctx context.Context, p *entity.SecretPolicy) error
	GetByID(ctx context.Context, id string) (*entity.SecretPolicy, error)
	// List returns organizationID's own tenant-defined policies plus
	// every platform-wide policy (OrganizationID nil) — mirrors
	// RoleRepository.List's identical split.
	List(ctx context.Context, organizationID string) ([]*entity.SecretPolicy, error)
	// Update changes only Name/Description — a policy's rules are
	// replaced via ReplaceRules, never mutated through this method.
	Update(ctx context.Context, p *entity.SecretPolicy) error
	// Delete cascades to the policy's rules, their actions, and every
	// role assignment (ON DELETE CASCADE, migrations/000027) — "deleted
	// policy no longer grants access" holds by construction: there is no
	// row left anywhere for ListRulesForRoles to find.
	Delete(ctx context.Context, id string) error

	// ReplaceRules atomically replaces every rule (and its actions)
	// belonging to policyID with rules — the whole set is swapped in one
	// transaction, not merged/diffed against the existing set. This is
	// the simplest semantics that has no ambiguity about "does this call
	// add to or overwrite what's there" — a caller that wants to add one
	// rule to an existing policy reads ListRules first, appends, and
	// calls ReplaceRules with the full resulting set.
	ReplaceRules(ctx context.Context, policyID string, rules []*entity.SecretPolicyRule) error
	ListRules(ctx context.Context, policyID string) ([]*entity.SecretPolicyRule, error)

	AssignToRole(ctx context.Context, a *entity.SecretPolicyRoleAssignment) error
	UnassignFromRole(ctx context.Context, policyID, roleID string) error
	// ListAssignedRoleIDs returns every role ID policyID is currently
	// assigned to — backs the admin "which roles have this policy" view.
	ListAssignedRoleIDs(ctx context.Context, policyID string) ([]string, error)

	// ListRulesForRoles is the PolicyEvaluator's entire data-access
	// footprint for one authorization decision: every rule (with its
	// actions already attached) belonging to a policy that is (a)
	// assigned to any role in roleIDs and (b) visible to organizationID
	// (its own tenant policies, plus every platform-wide one — see
	// entity.SecretPolicy's own doc comment on OrganizationID's
	// nullability). One query, not one per rule or per action — see
	// service.SecretPolicyService.Authorize's own doc comment on why this
	// is the only database round trip a single authorization check makes.
	ListRulesForRoles(ctx context.Context, organizationID string, roleIDs []string) ([]*entity.SecretPolicyRule, error)
}
