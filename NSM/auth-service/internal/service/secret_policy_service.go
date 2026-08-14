package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/policy"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// Permission strings SecretPolicyService checks for policy
// *administration* — deliberately a separate resource from secrets:*
// (migrations/000028): a role that can read and write secret values is
// not automatically a role that can decide which paths other roles may
// reach, the same separation roles:* already keeps from users:*.
const (
	permSecretPoliciesCreate = "secret_policies:create"
	permSecretPoliciesRead   = "secret_policies:read"
	permSecretPoliciesUpdate = "secret_policies:update"
	permSecretPoliciesDelete = "secret_policies:delete"
	permSecretPoliciesAssign = "secret_policies:assign"
)

// ErrEmptyPolicyRules means a policy was created or updated with zero
// rules — never a useful policy (it could never match anything, so every
// path it's consulted for falls through to default-deny), and far more
// likely a caller's mistake than an intentional "policy that grants
// nothing."
var ErrEmptyPolicyRules = errors.New("service: secret policy must have at least one rule")

// SecretPolicyService is Sprint 4 Task 2's authorization layer: secret
// policy administration (create/read/update/delete a policy, assign or
// unassign it to a role — all RBAC-gated the same way SecretService gates
// secrets:*) and the authorization decision itself, Authorize and
// FilterAllowedPaths, which SecretService calls after its own existing
// secrets:* permission check passes — see SecretService.authorizeSecretAccess's
// own doc comment for the exact "global permission, then path policy"
// ordering the objective requires.
//
// This service resolves which rules apply to a caller (their roles, via
// repository.UserRepository.ListRoles, then
// repository.SecretPolicyRepository.ListRulesForRoles) and hands them to
// internal/policy.Evaluate for the actual ALLOW/DENY decision — it does
// not implement path matching or precedence itself; see that package's
// own doc comment for why that logic lives there, deterministic and
// dependency-free, rather than here.
type SecretPolicyService struct {
	repo  repository.SecretPolicyRepository
	users repository.UserRepository
	// serviceAccounts (Sprint 5 Task 1) is roleIDsForActor's
	// machine-identity source of role grants — the same role
	// repository.UserRepository.ListRoles plays for a human actor. Never
	// nil in practice: cmd/server/main.go always constructs one alongside
	// users (see that file's own wiring).
	serviceAccounts repository.ServiceAccountRepository
	rbac            *RBACService
	auditTx         AuditTxFunc
}

// NewSecretPolicyService constructs a SecretPolicyService. auditTx may be
// nil, the same allowance every other AuditTx dependency in this codebase
// makes.
func NewSecretPolicyService(repo repository.SecretPolicyRepository, users repository.UserRepository, serviceAccounts repository.ServiceAccountRepository, rbac *RBACService, auditTx AuditTxFunc) *SecretPolicyService {
	return &SecretPolicyService{repo: repo, users: users, serviceAccounts: serviceAccounts, rbac: rbac, auditTx: auditTx}
}

// PolicyRuleInput is the caller-supplied shape of one rule — Effect
// defaults to "allow" when empty (the common case: most policies grant
// access, explicit deny is the exception, not the rule — pun
// unavoidable), and Actions must name at least one of
// policy.ActionRead/Create/Update/Delete/List.
type PolicyRuleInput struct {
	PathPattern string
	Effect      string
	Actions     []string
}

func (in PolicyRuleInput) toEntity() (*entity.SecretPolicyRule, error) {
	pattern := util.NormalizePolicyPathPattern(in.PathPattern)
	if err := util.ValidatePolicyPathPattern(pattern); err != nil {
		return nil, err
	}

	effect := entity.PolicyEffectAllow
	if in.Effect != "" {
		effect = entity.PolicyEffect(in.Effect)
		if effect != entity.PolicyEffectAllow && effect != entity.PolicyEffectDeny {
			return nil, fmt.Errorf(`service: rule effect must be "allow" or "deny", got %q`, in.Effect)
		}
	}

	if len(in.Actions) == 0 {
		return nil, fmt.Errorf("service: rule for path pattern %q must name at least one action", pattern)
	}
	actions := make([]entity.PolicyAction, 0, len(in.Actions))
	seen := make(map[entity.PolicyAction]bool, len(in.Actions))
	for _, a := range in.Actions {
		action := entity.PolicyAction(a)
		switch action {
		case entity.PolicyActionRead, entity.PolicyActionCreate, entity.PolicyActionUpdate, entity.PolicyActionDelete, entity.PolicyActionList, entity.PolicyActionRollback:
		default:
			return nil, fmt.Errorf("service: unknown policy action %q", a)
		}
		if seen[action] {
			continue
		}
		seen[action] = true
		actions = append(actions, action)
	}

	return &entity.SecretPolicyRule{PathPattern: pattern, Effect: effect, Actions: actions}, nil
}

func rulesFromInput(in []PolicyRuleInput) ([]*entity.SecretPolicyRule, error) {
	if len(in) == 0 {
		return nil, ErrEmptyPolicyRules
	}
	rules := make([]*entity.SecretPolicyRule, len(in))
	for i, r := range in {
		rule, err := r.toEntity()
		if err != nil {
			return nil, err
		}
		rules[i] = rule
	}
	return rules, nil
}

// CreatePolicyInput is CreatePolicy's argument. New policies created
// through this API are always tenant-scoped to OrganizationID — never
// platform-wide (OrganizationID nil in the entity is reserved for the
// migration-seeded default policy; there is no path through this service
// that creates another one). An organization's administrators managing
// their own policies is the entire point of this API; a platform-wide
// policy is a deliberately rarer, migration-only concept.
type CreatePolicyInput struct {
	OrganizationID string
	Name           string
	Description    string
	Rules          []PolicyRuleInput
	ActorUserID    string
	IPAddress      string
}

// CreatePolicy creates a policy and its rules atomically (Create, then
// ReplaceRules — see that repository method's own doc comment for why a
// fresh policy's rules are written the same way an existing one's are
// replaced, not a separate code path).
func (s *SecretPolicyService) CreatePolicy(ctx context.Context, in CreatePolicyInput) (*entity.SecretPolicy, error) {
	if err := s.authorize(ctx, in.ActorUserID, permSecretPoliciesCreate); err != nil {
		return nil, err
	}
	if in.Name == "" {
		return nil, fmt.Errorf("service: secret policy name is required")
	}
	rules, err := rulesFromInput(in.Rules)
	if err != nil {
		return nil, err
	}

	policyEntity := &entity.SecretPolicy{OrganizationID: &in.OrganizationID, Name: in.Name}
	if in.Description != "" {
		policyEntity.Description = &in.Description
	}
	if err := s.repo.Create(ctx, policyEntity); err != nil {
		return nil, err
	}
	if err := s.repo.ReplaceRules(ctx, policyEntity.ID, rules); err != nil {
		return nil, err
	}

	s.recordPolicyAudit(ctx, "policy.created", in.ActorUserID, policyEntity.ID, in.IPAddress, policyEntity.OrganizationID,
		map[string]any{"name": in.Name, "rule_count": len(rules)})
	return policyEntity, nil
}

// PolicyDetail is GetPolicy's return value — the policy plus its rules,
// bundled the way an admin UI actually needs to render a policy in one
// call rather than two.
type PolicyDetail struct {
	Policy *entity.SecretPolicy
	Rules  []*entity.SecretPolicyRule
}

func (s *SecretPolicyService) GetPolicy(ctx context.Context, actorUserID, policyID string) (PolicyDetail, error) {
	if err := s.authorize(ctx, actorUserID, permSecretPoliciesRead); err != nil {
		return PolicyDetail{}, err
	}
	p, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return PolicyDetail{}, err
	}
	rules, err := s.repo.ListRules(ctx, policyID)
	if err != nil {
		return PolicyDetail{}, err
	}
	return PolicyDetail{Policy: p, Rules: rules}, nil
}

func (s *SecretPolicyService) ListPolicies(ctx context.Context, actorUserID, organizationID string) ([]*entity.SecretPolicy, error) {
	if err := s.authorize(ctx, actorUserID, permSecretPoliciesRead); err != nil {
		return nil, err
	}
	return s.repo.List(ctx, organizationID)
}

// UpdatePolicyInput is UpdatePolicy's argument. Rules is nil-vs-empty
// significant: nil means "leave the existing rules alone" (a name/
// description-only edit); a non-nil, empty slice is rejected the same as
// CreatePolicy rejects it (ErrEmptyPolicyRules) rather than silently
// leaving a policy with no rules at all.
type UpdatePolicyInput struct {
	PolicyID    string
	Name        string
	Description string
	Rules       []PolicyRuleInput
	ActorUserID string
	IPAddress   string
}

func (s *SecretPolicyService) UpdatePolicy(ctx context.Context, in UpdatePolicyInput) (*entity.SecretPolicy, error) {
	if err := s.authorize(ctx, in.ActorUserID, permSecretPoliciesUpdate); err != nil {
		return nil, err
	}
	if in.Name == "" {
		return nil, fmt.Errorf("service: secret policy name is required")
	}

	p, err := s.repo.GetByID(ctx, in.PolicyID)
	if err != nil {
		return nil, err
	}
	p.Name = in.Name
	if in.Description != "" {
		p.Description = &in.Description
	} else {
		p.Description = nil
	}
	if err := s.repo.Update(ctx, p); err != nil {
		return nil, err
	}

	ruleCount := -1 // -1 signals "rules unchanged" in the audit entry below
	if in.Rules != nil {
		rules, err := rulesFromInput(in.Rules)
		if err != nil {
			return nil, err
		}
		if err := s.repo.ReplaceRules(ctx, p.ID, rules); err != nil {
			return nil, err
		}
		ruleCount = len(rules)
	}

	s.recordPolicyAudit(ctx, "policy.updated", in.ActorUserID, p.ID, in.IPAddress, p.OrganizationID,
		map[string]any{"name": p.Name, "rules_replaced": ruleCount >= 0, "rule_count": ruleCount})
	return p, nil
}

func (s *SecretPolicyService) DeletePolicy(ctx context.Context, actorUserID, policyID, ipAddress string) error {
	if err := s.authorize(ctx, actorUserID, permSecretPoliciesDelete); err != nil {
		return err
	}
	// Fetched first so the audit entry can name the policy even after the
	// row that would otherwise supply that name is gone — the same
	// "resolve what you're about to destroy before destroying it" order
	// SecretService.DeleteSecret's own audit call follows.
	p, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, policyID); err != nil {
		return err
	}
	s.recordPolicyAudit(ctx, "policy.deleted", actorUserID, policyID, ipAddress, p.OrganizationID, map[string]any{"name": p.Name})
	return nil
}

func (s *SecretPolicyService) AssignToRole(ctx context.Context, actorUserID, policyID, roleID, ipAddress string) error {
	if err := s.authorize(ctx, actorUserID, permSecretPoliciesAssign); err != nil {
		return err
	}
	// Fetched only for its OrganizationID (see recordPolicyAudit's own
	// OrganizationID parameter) — the same "resolve the org before
	// writing the audit entry" step Update/DeletePolicy already take.
	p, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return err
	}
	actor := actorUserID
	if err := s.repo.AssignToRole(ctx, &entity.SecretPolicyRoleAssignment{PolicyID: policyID, RoleID: roleID, AssignedBy: &actor}); err != nil {
		return err
	}
	s.recordPolicyAudit(ctx, "policy.assigned", actorUserID, policyID, ipAddress, p.OrganizationID, map[string]any{"role_id": roleID})
	return nil
}

func (s *SecretPolicyService) UnassignFromRole(ctx context.Context, actorUserID, policyID, roleID, ipAddress string) error {
	if err := s.authorize(ctx, actorUserID, permSecretPoliciesAssign); err != nil {
		return err
	}
	p, err := s.repo.GetByID(ctx, policyID)
	if err != nil {
		return err
	}
	if err := s.repo.UnassignFromRole(ctx, policyID, roleID); err != nil {
		return err
	}
	s.recordPolicyAudit(ctx, "policy.unassigned", actorUserID, policyID, ipAddress, p.OrganizationID, map[string]any{"role_id": roleID})
	return nil
}

func (s *SecretPolicyService) ListAssignedRoleIDs(ctx context.Context, actorUserID, policyID string) ([]string, error) {
	if err := s.authorize(ctx, actorUserID, permSecretPoliciesRead); err != nil {
		return nil, err
	}
	return s.repo.ListAssignedRoleIDs(ctx, policyID)
}

// --- Authorization decisions — called by SecretService, not gated by any
// secret_policies:* permission of their own: a caller reaching these
// methods has already passed SecretService's own secrets:* check, and
// what's being decided here is a restriction on top of that grant, not a
// separate capability to authorize. ---

// Authorize reports whether actorUserID's roles hold a policy that grants
// action on canonicalPath (already normalized — see util.NormalizeSecretPath;
// this method does not normalize it again). Exactly one database round
// trip beyond resolving the caller's roles: ListRulesForRoles fetches
// every applicable rule in one query, and internal/policy.Evaluate is a
// pure, in-memory decision over the result — see that function's own doc
// comment for the deny > allow > default-deny precedence.
func (s *SecretPolicyService) Authorize(ctx context.Context, actorID string, actorIsServiceAccount bool, organizationID, canonicalPath string, action policy.Action) (bool, error) {
	roleIDs, err := s.roleIDsForActor(ctx, actorID, actorIsServiceAccount)
	if err != nil {
		return false, err
	}
	rules, err := s.repo.ListRulesForRoles(ctx, organizationID, roleIDs)
	if err != nil {
		return false, err
	}
	return policy.Evaluate(toPolicyRules(rules), canonicalPath, action), nil
}

// FilterAllowedPaths returns the subset of paths actorUserID's roles hold
// a policy granting action for — GET /v1/secrets' own authorization
// requirement: the response must never include metadata for a path the
// caller has no policy for, even though listing and reading are
// different actions this codebase already distinguishes (secrets:list vs
// secrets:read). Rules are resolved once, not once per path — the same
// "one query, then in-memory evaluation" shape Authorize uses, extended
// to many paths instead of one, so this scales with the size of the
// caller's rule set, not the size of the secret list.
func (s *SecretPolicyService) FilterAllowedPaths(ctx context.Context, actorID string, actorIsServiceAccount bool, organizationID string, paths []string, action policy.Action) ([]string, error) {
	roleIDs, err := s.roleIDsForActor(ctx, actorID, actorIsServiceAccount)
	if err != nil {
		return nil, err
	}
	rules, err := s.repo.ListRulesForRoles(ctx, organizationID, roleIDs)
	if err != nil {
		return nil, err
	}
	prules := toPolicyRules(rules)

	allowed := make([]string, 0, len(paths))
	for _, p := range paths {
		if policy.Evaluate(prules, p, action) {
			allowed = append(allowed, p)
		}
	}
	return allowed, nil
}

// roleIDsForActor resolves actorID's current role grants — a human
// actor's via repository.UserRepository.ListRoles (which also filters
// expired grants at the SQL level, the identical filtering
// RBACRepository.UserHasPermission applies for the base permission check,
// so a role that has expired stops contributing policy rules at exactly
// the same moment it stops contributing permissions), or a service
// account's via repository.ServiceAccountRepository.ListRoles (Sprint 5
// Task 1 — service_account_roles grants have no expiry column at all, see
// that repository interface's own doc comment on why). Which one this
// calls is never guessed from actorID's shape — both are opaque UUIDs —
// only from actorIsServiceAccount, the same explicit signal every other
// identity-type dispatch in this codebase (RequirePermission,
// SecretService.authorize) already uses.
func (s *SecretPolicyService) roleIDsForActor(ctx context.Context, actorID string, actorIsServiceAccount bool) ([]string, error) {
	if actorIsServiceAccount {
		grants, err := s.serviceAccounts.ListRoles(ctx, actorID)
		if err != nil {
			return nil, err
		}
		ids := make([]string, len(grants))
		for i, g := range grants {
			ids[i] = g.RoleID
		}
		return ids, nil
	}
	grants, err := s.users.ListRoles(ctx, actorID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(grants))
	for i, g := range grants {
		ids[i] = g.RoleID
	}
	return ids, nil
}

func toPolicyRules(rules []*entity.SecretPolicyRule) []policy.Rule {
	out := make([]policy.Rule, len(rules))
	for i, r := range rules {
		actions := make([]policy.Action, len(r.Actions))
		for j, a := range r.Actions {
			actions[j] = policy.Action(a)
		}
		out[i] = policy.Rule{PathPattern: r.PathPattern, Effect: policy.Effect(r.Effect), Actions: actions}
	}
	return out
}

func (s *SecretPolicyService) authorize(ctx context.Context, actorUserID, permission string) error {
	if actorUserID == "" {
		return entity.ErrForbidden
	}
	allowed, err := s.rbac.HasPermission(ctx, actorUserID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}
	return nil
}

// recordPolicyAudit is best-effort, matching every other recordXAudit in
// this codebase — see SecretService.recordSecretAudit's own doc comment.
// metadata never carries a path pattern's... actually it may: path
// patterns are policy *configuration*, the administrative shape of who
// can reach what, not a secret value or key material — safe to sit in
// audit_logs indefinitely, the same way secret *paths* (not values)
// already do in SecretService's own audit entries.
func (s *SecretPolicyService) recordPolicyAudit(ctx context.Context, action, actorUserID, policyID, ipAddress string, organizationID *string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	var actorID *string
	if actorUserID != "" {
		actorID = &actorUserID
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: organizationID,
			ActorType:      entity.AuditActorUser,
			ActorID:        actorID,
			Action:         action,
			ResourceType:   strPtr("secret_policy"),
			ResourceID:     strPtr(policyID),
			Result:         entity.AuditResultSuccess,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record audit event",
			zap.String("action", action), zap.String("policy_id", policyID), zap.Error(err))
	}
}
