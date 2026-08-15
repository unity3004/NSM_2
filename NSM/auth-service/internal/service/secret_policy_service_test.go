package service

import (
	"errors"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/policy"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/util"
)

const (
	policyTestOrgID = "org-policy-1"
	policyAdminID   = "user-policy-admin"
	policyNobodyID  = "user-policy-nobody"
	policyRoleDev   = "role-policy-dev"
	policyRoleProd  = "role-policy-prod"
)

type testPolicyEnv struct {
	svc   *SecretPolicyService
	repo  *mocks.FakeSecretPolicyRepository
	users *mocks.FakeUserRepository
	rbac  *mocks.FakeRBACRepository
	audit *mocks.FakeAuditLogRepository
}

// newTestPolicyEnv wires a SecretPolicyService against in-memory fakes.
// policyAdminID is pre-granted every secret_policies:* permission;
// policyNobodyID is granted none — the same "administrator vs. nobody"
// split newTestSecretEnv already establishes for secrets:* itself.
func newTestPolicyEnv(t *testing.T) *testPolicyEnv {
	t.Helper()
	repo := mocks.NewFakeSecretPolicyRepository()
	users := mocks.NewFakeUserRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := NewRBACService(rbacRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	rbacRepo.Grant(policyAdminID, permSecretPoliciesCreate)
	rbacRepo.Grant(policyAdminID, permSecretPoliciesRead)
	rbacRepo.Grant(policyAdminID, permSecretPoliciesUpdate)
	rbacRepo.Grant(policyAdminID, permSecretPoliciesDelete)
	rbacRepo.Grant(policyAdminID, permSecretPoliciesAssign)

	svc := NewSecretPolicyService(repo, users, mocks.NewFakeServiceAccountRepository(), rbacSvc, auditTx)
	return &testPolicyEnv{svc: svc, repo: repo, users: users, rbac: rbacRepo, audit: audit}
}

func devRule() PolicyRuleInput {
	return PolicyRuleInput{PathPattern: "dev/*", Actions: []string{"read", "create", "update"}}
}

// --- 19/20: admin can manage policies, non-admin cannot ---

func TestSecretPolicyService_CreatePolicy_RequiresPermission(t *testing.T) {
	env := newTestPolicyEnv(t)
	_, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Rules: []PolicyRuleInput{devRule()}, ActorUserID: policyNobodyID,
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("CreatePolicy() by a user without secret_policies:create, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretPolicyService_CreatePolicy_UnauthenticatedDenied(t *testing.T) {
	env := newTestPolicyEnv(t)
	_, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Rules: []PolicyRuleInput{devRule()}, ActorUserID: "",
	})
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("CreatePolicy() with no actor, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretPolicyService_CreatePolicy_Succeeds(t *testing.T) {
	env := newTestPolicyEnv(t)
	p, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Description: "grants dev access",
		Rules: []PolicyRuleInput{devRule()}, ActorUserID: policyAdminID, IPAddress: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
	if p.ID == "" || p.Name != "dev-access" {
		t.Errorf("CreatePolicy() = %+v, want a persisted policy named dev-access", p)
	}

	detail, err := env.svc.GetPolicy(t.Context(), policyAdminID, p.ID)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if len(detail.Rules) != 1 || detail.Rules[0].PathPattern != "dev/*" {
		t.Errorf("GetPolicy() rules = %+v, want one rule for dev/*", detail.Rules)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "policy.created" && e.ResourceID != nil && *e.ResourceID == p.ID {
			found = true
			// Audit-logging phase regression test: OrganizationID was
			// previously never set on any recordPolicyAudit call, making
			// every policy.* row invisible to AuditService.ListAuditLogs'
			// own organization-scoped query.
			if e.OrganizationID == nil || *e.OrganizationID != policyTestOrgID {
				t.Errorf("policy.created audit OrganizationID = %v, want %q", e.OrganizationID, policyTestOrgID)
			}
		}
	}
	if !found {
		t.Error("no policy.created audit entry was recorded")
	}
}

func TestSecretPolicyService_CreatePolicy_EmptyRulesRejected(t *testing.T) {
	env := newTestPolicyEnv(t)
	_, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "empty", Rules: nil, ActorUserID: policyAdminID,
	})
	if !errors.Is(err, ErrEmptyPolicyRules) {
		t.Errorf("CreatePolicy() with zero rules, error = %v, want ErrEmptyPolicyRules", err)
	}
}

func TestSecretPolicyService_CreatePolicy_InvalidPathPatternRejected(t *testing.T) {
	env := newTestPolicyEnv(t)
	_, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "bad-pattern",
		Rules:       []PolicyRuleInput{{PathPattern: "prod/../etc", Actions: []string{"read"}}},
		ActorUserID: policyAdminID,
	})
	if !errors.Is(err, util.ErrInvalidPolicyPattern) {
		t.Errorf("CreatePolicy() with a traversal path pattern, error = %v, want util.ErrInvalidPolicyPattern", err)
	}
}

func TestSecretPolicyService_CreatePolicy_UnknownActionRejected(t *testing.T) {
	env := newTestPolicyEnv(t)
	_, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "bad-action",
		Rules:       []PolicyRuleInput{{PathPattern: "dev/*", Actions: []string{"execute"}}},
		ActorUserID: policyAdminID,
	})
	if err == nil {
		t.Error("CreatePolicy() with an unknown action = nil error, want a rejection")
	}
}

func TestSecretPolicyService_ListPolicies_RequiresPermission(t *testing.T) {
	env := newTestPolicyEnv(t)
	_, err := env.svc.ListPolicies(t.Context(), policyNobodyID, policyTestOrgID)
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ListPolicies() without secret_policies:read, error = %v, want entity.ErrForbidden", err)
	}
}

// --- 15/16: policy changes affect authorization; a deleted policy no
// longer grants access ---

func TestSecretPolicyService_UpdatePolicy_NilRulesLeavesExistingRulesUnchanged(t *testing.T) {
	env := newTestPolicyEnv(t)
	p, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Rules: []PolicyRuleInput{devRule()}, ActorUserID: policyAdminID,
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	if _, err := env.svc.UpdatePolicy(t.Context(), UpdatePolicyInput{
		PolicyID: p.ID, Name: "dev-access-renamed", Rules: nil, ActorUserID: policyAdminID,
	}); err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}

	detail, err := env.svc.GetPolicy(t.Context(), policyAdminID, p.ID)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if detail.Policy.Name != "dev-access-renamed" {
		t.Errorf("Policy.Name = %q, want dev-access-renamed", detail.Policy.Name)
	}
	if len(detail.Rules) != 1 || detail.Rules[0].PathPattern != "dev/*" {
		t.Errorf("rules after a nil-Rules update = %+v, want the original single dev/* rule untouched", detail.Rules)
	}
}

func TestSecretPolicyService_UpdatePolicy_EmptyNonNilRulesRejected(t *testing.T) {
	env := newTestPolicyEnv(t)
	p, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Rules: []PolicyRuleInput{devRule()}, ActorUserID: policyAdminID,
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
	_, err = env.svc.UpdatePolicy(t.Context(), UpdatePolicyInput{
		PolicyID: p.ID, Name: "dev-access", Rules: []PolicyRuleInput{}, ActorUserID: policyAdminID,
	})
	if !errors.Is(err, ErrEmptyPolicyRules) {
		t.Errorf("UpdatePolicy() with an explicit empty Rules slice, error = %v, want ErrEmptyPolicyRules", err)
	}
}

func TestSecretPolicyService_DeletePolicy_RemovesGrantEntirely(t *testing.T) {
	env := newTestPolicyEnv(t)
	p, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Rules: []PolicyRuleInput{devRule()}, ActorUserID: policyAdminID,
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
	if err := env.svc.AssignToRole(t.Context(), policyAdminID, p.ID, policyRoleDev, ""); err != nil {
		t.Fatalf("AssignToRole() error = %v", err)
	}
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-dev", RoleID: policyRoleDev}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	allowed, err := env.svc.Authorize(t.Context(), "user-dev", false, policyTestOrgID, "dev/database", policy.ActionRead)
	if err != nil {
		t.Fatalf("Authorize() before delete, error = %v", err)
	}
	if !allowed {
		t.Fatal("Authorize() before delete = false, want true")
	}

	if err := env.svc.DeletePolicy(t.Context(), policyAdminID, p.ID, ""); err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	allowed, err = env.svc.Authorize(t.Context(), "user-dev", false, policyTestOrgID, "dev/database", policy.ActionRead)
	if err != nil {
		t.Fatalf("Authorize() after delete, error = %v", err)
	}
	if allowed {
		t.Error("Authorize() after DeletePolicy = true, want false — a deleted policy must no longer grant access")
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "policy.deleted" && e.ResourceID != nil && *e.ResourceID == p.ID {
			found = true
		}
	}
	if !found {
		t.Error("no policy.deleted audit entry was recorded")
	}
}

// --- assignment gating and audit ---

func TestSecretPolicyService_AssignToRole_RequiresPermission(t *testing.T) {
	env := newTestPolicyEnv(t)
	p := env.repo.SeedPolicy(&entity.SecretPolicy{Name: "seeded"})
	err := env.svc.AssignToRole(t.Context(), policyNobodyID, p.ID, policyRoleDev, "")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("AssignToRole() without secret_policies:assign, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretPolicyService_UnassignFromRole_RequiresPermission(t *testing.T) {
	env := newTestPolicyEnv(t)
	p := env.repo.SeedPolicy(&entity.SecretPolicy{Name: "seeded"})
	env.repo.AssignRole(p.ID, policyRoleDev)
	err := env.svc.UnassignFromRole(t.Context(), policyNobodyID, p.ID, policyRoleDev, "")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("UnassignFromRole() without secret_policies:assign, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretPolicyService_ListAssignedRoleIDs_RequiresPermission(t *testing.T) {
	env := newTestPolicyEnv(t)
	p := env.repo.SeedPolicy(&entity.SecretPolicy{Name: "seeded"})
	_, err := env.svc.ListAssignedRoleIDs(t.Context(), policyNobodyID, p.ID)
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ListAssignedRoleIDs() without secret_policies:read, error = %v, want entity.ErrForbidden", err)
	}
}

func TestSecretPolicyService_AssignThenUnassign_RoundTrips(t *testing.T) {
	env := newTestPolicyEnv(t)
	p, err := env.svc.CreatePolicy(t.Context(), CreatePolicyInput{
		OrganizationID: policyTestOrgID, Name: "dev-access", Rules: []PolicyRuleInput{devRule()}, ActorUserID: policyAdminID,
	})
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
	if err := env.svc.AssignToRole(t.Context(), policyAdminID, p.ID, policyRoleDev, ""); err != nil {
		t.Fatalf("AssignToRole() error = %v", err)
	}
	ids, err := env.svc.ListAssignedRoleIDs(t.Context(), policyAdminID, p.ID)
	if err != nil || len(ids) != 1 || ids[0] != policyRoleDev {
		t.Fatalf("ListAssignedRoleIDs() = %v, %v; want [%q], nil", ids, err, policyRoleDev)
	}

	if err := env.svc.UnassignFromRole(t.Context(), policyAdminID, p.ID, policyRoleDev, ""); err != nil {
		t.Fatalf("UnassignFromRole() error = %v", err)
	}
	ids, err = env.svc.ListAssignedRoleIDs(t.Context(), policyAdminID, p.ID)
	if err != nil || len(ids) != 0 {
		t.Fatalf("ListAssignedRoleIDs() after unassign = %v, %v; want empty, nil", ids, err)
	}
}

// --- authorization decisions: deny by default, path matching, precedence ---

func TestSecretPolicyService_Authorize_DeniesByDefault_NoPolicyAtAll(t *testing.T) {
	env := newTestPolicyEnv(t)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-x", RoleID: policyRoleDev}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}
	allowed, err := env.svc.Authorize(t.Context(), "user-x", false, policyTestOrgID, "dev/database", policy.ActionRead)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if allowed {
		t.Error("Authorize() with no policy assigned to the caller's role = true, want false (deny by default)")
	}
}

func TestSecretPolicyService_Authorize_MatchingPolicyGrantsAccess(t *testing.T) {
	env := newTestPolicyEnv(t)
	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p-dev", Name: "dev"})
	env.repo.SeedRule("p-dev", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionRead},
	})
	env.repo.AssignRole("p-dev", policyRoleDev)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-dev", RoleID: policyRoleDev}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	allowed, err := env.svc.Authorize(t.Context(), "user-dev", false, policyTestOrgID, "dev/database", policy.ActionRead)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if !allowed {
		t.Error("Authorize() for dev/database read with a matching dev/* allow policy = false, want true")
	}

	allowed, err = env.svc.Authorize(t.Context(), "user-dev", false, policyTestOrgID, "prod/database", policy.ActionRead)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if allowed {
		t.Error("Authorize() for prod/database with only a dev/* policy = true, want false")
	}
}

func TestSecretPolicyService_Authorize_SimilarPathDoesNotBypass(t *testing.T) {
	env := newTestPolicyEnv(t)
	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p-narrow", Name: "narrow"})
	env.repo.SeedRule("p-narrow", &entity.SecretPolicyRule{
		PathPattern: "prod/db", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionRead},
	})
	env.repo.AssignRole("p-narrow", policyRoleProd)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-prod", RoleID: policyRoleProd}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	allowed, err := env.svc.Authorize(t.Context(), "user-prod", false, policyTestOrgID, "prod/database", policy.ActionRead)
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if allowed {
		t.Error(`Authorize() for "prod/database" with a "prod/db" exact-match policy = true, want false`)
	}
}

func TestSecretPolicyService_Authorize_ExplicitDenyPrecedence(t *testing.T) {
	env := newTestPolicyEnv(t)
	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p-broad", Name: "broad"})
	env.repo.SeedRule("p-broad", &entity.SecretPolicyRule{
		PathPattern: "prod/*", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionRead},
	})
	env.repo.AssignRole("p-broad", policyRoleProd)

	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p-deny", Name: "deny-secrets"})
	env.repo.SeedRule("p-deny", &entity.SecretPolicyRule{
		PathPattern: "prod/secrets/*", Effect: entity.PolicyEffectDeny,
		Actions: []entity.PolicyAction{entity.PolicyActionRead},
	})
	env.repo.AssignRole("p-deny", policyRoleProd)

	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-prod", RoleID: policyRoleProd}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	allowed, err := env.svc.Authorize(t.Context(), "user-prod", false, policyTestOrgID, "prod/database", policy.ActionRead)
	if err != nil || !allowed {
		t.Errorf("Authorize(prod/database) = %v, %v; want true, nil", allowed, err)
	}
	allowed, err = env.svc.Authorize(t.Context(), "user-prod", false, policyTestOrgID, "prod/secrets/token", policy.ActionRead)
	if err != nil || allowed {
		t.Errorf("Authorize(prod/secrets/token) = %v, %v; want false, nil — explicit deny must win over the broader allow", allowed, err)
	}
}

func TestSecretPolicyService_Authorize_MultiplePoliciesDeterministic(t *testing.T) {
	env := newTestPolicyEnv(t)
	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p1", Name: "p1"})
	env.repo.SeedRule("p1", &entity.SecretPolicyRule{PathPattern: "dev/*", Effect: entity.PolicyEffectAllow, Actions: []entity.PolicyAction{entity.PolicyActionRead}})
	env.repo.AssignRole("p1", policyRoleDev)

	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p2", Name: "p2"})
	env.repo.SeedRule("p2", &entity.SecretPolicyRule{PathPattern: "staging/*", Effect: entity.PolicyEffectAllow, Actions: []entity.PolicyAction{entity.PolicyActionRead}})
	env.repo.AssignRole("p2", policyRoleDev)

	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-multi", RoleID: policyRoleDev}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	for i := 0; i < 5; i++ {
		allowed, err := env.svc.Authorize(t.Context(), "user-multi", false, policyTestOrgID, "staging/db", policy.ActionRead)
		if err != nil || !allowed {
			t.Fatalf("iteration %d: Authorize(staging/db) = %v, %v; want true, nil", i, allowed, err)
		}
	}
}

// --- FilterAllowedPaths: list authorization must never reveal an
// unauthorized path's metadata ---

func TestSecretPolicyService_FilterAllowedPaths_OnlyReturnsAuthorizedPaths(t *testing.T) {
	env := newTestPolicyEnv(t)
	env.repo.SeedPolicy(&entity.SecretPolicy{ID: "p-dev", Name: "dev"})
	env.repo.SeedRule("p-dev", &entity.SecretPolicyRule{
		PathPattern: "dev/*", Effect: entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{entity.PolicyActionList},
	})
	env.repo.AssignRole("p-dev", policyRoleDev)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-dev", RoleID: policyRoleDev}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}

	all := []string{"dev/database", "dev/api", "prod/database", "prod/payment"}
	allowed, err := env.svc.FilterAllowedPaths(t.Context(), "user-dev", false, policyTestOrgID, all, policy.ActionList)
	if err != nil {
		t.Fatalf("FilterAllowedPaths() error = %v", err)
	}
	want := map[string]bool{"dev/database": true, "dev/api": true}
	if len(allowed) != len(want) {
		t.Fatalf("FilterAllowedPaths() = %v, want exactly %v", allowed, want)
	}
	for _, p := range allowed {
		if !want[p] {
			t.Errorf("FilterAllowedPaths() unexpectedly included unauthorized path %q", p)
		}
	}
}

func TestSecretPolicyService_FilterAllowedPaths_EmptyInput(t *testing.T) {
	env := newTestPolicyEnv(t)
	allowed, err := env.svc.FilterAllowedPaths(t.Context(), policyAdminID, false, policyTestOrgID, nil, policy.ActionList)
	if err != nil {
		t.Fatalf("FilterAllowedPaths() error = %v", err)
	}
	if len(allowed) != 0 {
		t.Errorf("FilterAllowedPaths(nil) = %v, want empty", allowed)
	}
}

// --- GrantFullAccessToRole helper sanity (used across the rest of this
// service's test suite and secret_service_test.go) ---

func TestSecretPolicyService_GrantFullAccessToRole_GrantsEveryAction(t *testing.T) {
	env := newTestPolicyEnv(t)
	env.repo.GrantFullAccessToRole(policyRoleDev)
	if err := env.users.GrantRole(t.Context(), &entity.UserRole{UserID: "user-full", RoleID: policyRoleDev}); err != nil {
		t.Fatalf("GrantRole() error = %v", err)
	}
	for _, action := range []policy.Action{policy.ActionRead, policy.ActionCreate, policy.ActionUpdate, policy.ActionDelete, policy.ActionList} {
		allowed, err := env.svc.Authorize(t.Context(), "user-full", false, policyTestOrgID, "any/path/at/all", action)
		if err != nil || !allowed {
			t.Errorf("Authorize(action=%s) with full access = %v, %v; want true, nil", action, allowed, err)
		}
	}
}
