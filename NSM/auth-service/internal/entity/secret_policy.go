package entity

import "time"

// SecretPolicy is a named, reusable bundle of path-authorization rules —
// see migrations/000027_create_secret_policies's own doc comment for why
// this mirrors Role's shape (including nullable OrganizationID: nil means
// a platform-wide policy usable by any organization whose user holds an
// assigned role, exactly like a system-wide Role) rather than a new one.
type SecretPolicy struct {
	ID             string
	OrganizationID *string
	Name           string
	Description    *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// PolicyEffect mirrors the secret_policy_effect Postgres enum — the
// entity-layer counterpart to policy.Effect (internal/policy), kept as a
// separate type because internal/policy deliberately has no dependency on
// internal/entity (see that package's own doc comment); repository code
// converts between the two.
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// PolicyAction mirrors the secret_policy_action Postgres enum — the
// entity-layer counterpart to policy.Action, for the same reason.
type PolicyAction string

const (
	PolicyActionRead   PolicyAction = "read"
	PolicyActionCreate PolicyAction = "create"
	PolicyActionUpdate PolicyAction = "update"
	PolicyActionDelete PolicyAction = "delete"
	PolicyActionList   PolicyAction = "list"
)

// SecretPolicyRule is one secret_policy_rules row plus its joined
// secret_policy_rule_actions rows — a policy's individual (path_pattern,
// effect, actions) grant or restriction. PathPattern is stored already
// normalized (util.NormalizePolicyPathPattern) — see that function's own
// doc comment.
type SecretPolicyRule struct {
	ID          string
	PolicyID    string
	PathPattern string
	Effect      PolicyEffect
	Actions     []PolicyAction
	CreatedAt   time.Time
}

// SecretPolicyRoleAssignment is a secret_policy_role_assignments row — a
// policy granted to every member of a role, mirroring UserRole/GroupRole's
// own "the grant itself is its own row" shape.
type SecretPolicyRoleAssignment struct {
	PolicyID   string
	RoleID     string
	AssignedBy *string
	AssignedAt time.Time
}
