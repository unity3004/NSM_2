//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
)

// seedTestPolicy creates a real secret_policies row (with one rule) via
// the real repository, so every test below exercises the actual SQL
// (INSERT ... RETURNING, the ReplaceRules transaction) rather than
// constructing rows by hand — the same "use the real repository to set up
// its own fixtures" approach seedSecretTestUser already establishes for
// secrets.
func seedTestPolicy(t *testing.T, db *sql.DB, name string, rules []*entity.SecretPolicyRule) *entity.SecretPolicy {
	t.Helper()
	repo := postgres.NewSecretPolicyRepository(db)
	p := &entity.SecretPolicy{OrganizationID: strPtrForTest(secretTestOrgID), Name: name}
	if err := repo.Create(context.Background(), p); err != nil {
		t.Fatalf("Create(%q): %v", name, err)
	}
	if err := repo.ReplaceRules(context.Background(), p.ID, rules); err != nil {
		t.Fatalf("ReplaceRules(%q): %v", name, err)
	}
	return p
}

func allowRule(pattern string, actions ...entity.PolicyAction) *entity.SecretPolicyRule {
	return &entity.SecretPolicyRule{PathPattern: pattern, Effect: entity.PolicyEffectAllow, Actions: actions}
}

// 1. Create + GetByID round-trip.
func TestSecretPolicyRepository_CreateAndGetByID(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	p := &entity.SecretPolicy{OrganizationID: strPtrForTest(secretTestOrgID), Name: "it-create-" + t.Name(), Description: strPtrForTest("integration test policy")}
	if err := repo.Create(ctx, p); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if p.ID == "" {
		t.Fatal("Create() did not assign an ID")
	}

	got, err := repo.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.Name != p.Name || got.OrganizationID == nil || *got.OrganizationID != secretTestOrgID {
		t.Errorf("GetByID() = %+v, want Name=%q OrganizationID=%q", got, p.Name, secretTestOrgID)
	}
}

func TestSecretPolicyRepository_GetByID_NotFound(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	_, err := repo.GetByID(context.Background(), "00000000-0000-4000-9000-999999999999")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetByID() for a nonexistent ID, error = %v, want entity.ErrNotFound", err)
	}
}

// 2. uq_secret_policies_org_name is enforced.
func TestSecretPolicyRepository_Create_DuplicateNameInOrgRejected(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()
	name := "it-dup-" + t.Name()

	if err := repo.Create(ctx, &entity.SecretPolicy{OrganizationID: strPtrForTest(secretTestOrgID), Name: name}); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}
	err := repo.Create(ctx, &entity.SecretPolicy{OrganizationID: strPtrForTest(secretTestOrgID), Name: name})
	if !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("duplicate Create() error = %v, want entity.ErrAlreadyExists", err)
	}
}

// 3. List returns this org's own policies plus platform-wide ones.
func TestSecretPolicyRepository_List_ReturnsOrgAndPlatformWide(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	orgScoped := &entity.SecretPolicy{OrganizationID: strPtrForTest(secretTestOrgID), Name: "it-list-org-" + t.Name()}
	if err := repo.Create(ctx, orgScoped); err != nil {
		t.Fatalf("Create(org-scoped) error = %v", err)
	}
	platformWide := &entity.SecretPolicy{OrganizationID: nil, Name: "it-list-platform-" + t.Name()}
	if err := repo.Create(ctx, platformWide); err != nil {
		t.Fatalf("Create(platform-wide) error = %v", err)
	}

	list, err := repo.List(ctx, secretTestOrgID)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	var sawOrg, sawPlatform bool
	for _, p := range list {
		if p.ID == orgScoped.ID {
			sawOrg = true
		}
		if p.ID == platformWide.ID {
			sawPlatform = true
		}
	}
	if !sawOrg {
		t.Error("List() did not include the org-scoped policy")
	}
	if !sawPlatform {
		t.Error("List() did not include the platform-wide (organization_id IS NULL) policy")
	}
}

// 4. Update changes only Name/Description.
func TestSecretPolicyRepository_Update(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	p := seedTestPolicy(t, db, "it-update-"+t.Name(), []*entity.SecretPolicyRule{allowRule("dev/*", entity.PolicyActionRead)})
	p.Name = p.Name + "-renamed"
	p.Description = strPtrForTest("updated description")
	if err := repo.Update(ctx, p); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	got, err := repo.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.Name != p.Name || got.Description == nil || *got.Description != "updated description" {
		t.Errorf("GetByID() after Update() = %+v, want Name=%q", got, p.Name)
	}

	rules, err := repo.ListRules(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListRules() error = %v", err)
	}
	if len(rules) != 1 || rules[0].PathPattern != "dev/*" {
		t.Errorf("Update() unexpectedly touched rules: %+v, want the original single dev/* rule untouched", rules)
	}
}

// 5. ReplaceRules atomically swaps the entire rule set.
func TestSecretPolicyRepository_ReplaceRules_AtomicSwap(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	p := seedTestPolicy(t, db, "it-replace-"+t.Name(), []*entity.SecretPolicyRule{
		allowRule("dev/*", entity.PolicyActionRead, entity.PolicyActionCreate),
		allowRule("staging/*", entity.PolicyActionRead),
	})

	rules, err := repo.ListRules(ctx, p.ID)
	if err != nil || len(rules) != 2 {
		t.Fatalf("ListRules() before replace = %v, %v; want 2 rules, nil", rules, err)
	}

	if err := repo.ReplaceRules(ctx, p.ID, []*entity.SecretPolicyRule{
		allowRule("prod/*", entity.PolicyActionRead),
	}); err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	rules, err = repo.ListRules(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListRules() after replace, error = %v", err)
	}
	if len(rules) != 1 || rules[0].PathPattern != "prod/*" {
		t.Errorf("ListRules() after ReplaceRules() = %+v, want exactly one prod/* rule — the old dev/*/staging/* rules must be gone, not merged", rules)
	}
}

// 6. ListRules attaches actions correctly (attachActions' bulk join).
func TestSecretPolicyRepository_ListRules_ReturnsActions(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	p := seedTestPolicy(t, db, "it-actions-"+t.Name(), []*entity.SecretPolicyRule{
		allowRule("dev/*", entity.PolicyActionRead, entity.PolicyActionCreate, entity.PolicyActionUpdate),
	})

	rules, err := repo.ListRules(ctx, p.ID)
	if err != nil {
		t.Fatalf("ListRules() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("ListRules() returned %d rules, want 1", len(rules))
	}
	want := map[entity.PolicyAction]bool{entity.PolicyActionRead: true, entity.PolicyActionCreate: true, entity.PolicyActionUpdate: true}
	if len(rules[0].Actions) != len(want) {
		t.Fatalf("rule.Actions = %v, want exactly %v", rules[0].Actions, want)
	}
	for _, a := range rules[0].Actions {
		if !want[a] {
			t.Errorf("rule.Actions contained unexpected action %q", a)
		}
	}
}

// 7. Assign/unassign a role.
func TestSecretPolicyRepository_AssignAndUnassignRole(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	p := seedTestPolicy(t, db, "it-assign-"+t.Name(), []*entity.SecretPolicyRule{allowRule("dev/*", entity.PolicyActionRead)})

	if err := repo.AssignToRole(ctx, &entity.SecretPolicyRoleAssignment{PolicyID: p.ID, RoleID: developerRoleID}); err != nil {
		t.Fatalf("AssignToRole() error = %v", err)
	}
	ids, err := repo.ListAssignedRoleIDs(ctx, p.ID)
	if err != nil || len(ids) != 1 || ids[0] != developerRoleID {
		t.Fatalf("ListAssignedRoleIDs() = %v, %v; want [%q], nil", ids, err, developerRoleID)
	}

	if err := repo.UnassignFromRole(ctx, p.ID, developerRoleID); err != nil {
		t.Fatalf("UnassignFromRole() error = %v", err)
	}
	ids, err = repo.ListAssignedRoleIDs(ctx, p.ID)
	if err != nil || len(ids) != 0 {
		t.Fatalf("ListAssignedRoleIDs() after unassign = %v, %v; want empty, nil", ids, err)
	}
}

func TestSecretPolicyRepository_UnassignFromRole_NotFound(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	p := seedTestPolicy(t, db, "it-unassign-notfound-"+t.Name(), []*entity.SecretPolicyRule{allowRule("dev/*", entity.PolicyActionRead)})

	err := repo.UnassignFromRole(context.Background(), p.ID, developerRoleID)
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("UnassignFromRole() for an assignment that was never made, error = %v, want entity.ErrNotFound", err)
	}
}

// 8/9. ListRulesForRoles is the evaluator's real data-access path: joins
// role assignment AND organization visibility correctly, and never
// returns a rule belonging to a role not in roleIDs or a policy not
// visible to organizationID.
func TestSecretPolicyRepository_ListRulesForRoles_JoinsCorrectly(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	devPolicy := seedTestPolicy(t, db, "it-join-dev-"+t.Name(), []*entity.SecretPolicyRule{allowRule("dev/*", entity.PolicyActionRead)})
	if err := repo.AssignToRole(ctx, &entity.SecretPolicyRoleAssignment{PolicyID: devPolicy.ID, RoleID: developerRoleID}); err != nil {
		t.Fatalf("AssignToRole(developer) error = %v", err)
	}

	adminOnlyPolicy := seedTestPolicy(t, db, "it-join-admin-"+t.Name(), []*entity.SecretPolicyRule{allowRule("prod/*", entity.PolicyActionRead)})
	if err := repo.AssignToRole(ctx, &entity.SecretPolicyRoleAssignment{PolicyID: adminOnlyPolicy.ID, RoleID: platformAdminRoleID}); err != nil {
		t.Fatalf("AssignToRole(admin) error = %v", err)
	}

	rules, err := repo.ListRulesForRoles(ctx, secretTestOrgID, []string{developerRoleID})
	if err != nil {
		t.Fatalf("ListRulesForRoles([developer]) error = %v", err)
	}
	var sawDevRule, sawAdminRule bool
	for _, r := range rules {
		if r.PolicyID == devPolicy.ID {
			sawDevRule = true
		}
		if r.PolicyID == adminOnlyPolicy.ID {
			sawAdminRule = true
		}
	}
	if !sawDevRule {
		t.Error("ListRulesForRoles([developer]) did not include the policy assigned to developerRoleID")
	}
	if sawAdminRule {
		t.Error("ListRulesForRoles([developer]) unexpectedly included a policy assigned only to platformAdminRoleID — role scoping is broken")
	}
}

func TestSecretPolicyRepository_ListRulesForRoles_EmptyRoleIDs(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	rules, err := repo.ListRulesForRoles(context.Background(), secretTestOrgID, nil)
	if err != nil {
		t.Fatalf("ListRulesForRoles(nil) error = %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("ListRulesForRoles(nil) = %v, want empty", rules)
	}
}

// 16. Delete cascades to rules, their actions, and every role assignment
// — "deleted policy no longer grants access" holds by construction.
func TestSecretPolicyRepository_Delete_CascadesToRulesAndAssignments(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	p := seedTestPolicy(t, db, "it-cascade-"+t.Name(), []*entity.SecretPolicyRule{allowRule("dev/*", entity.PolicyActionRead)})
	if err := repo.AssignToRole(ctx, &entity.SecretPolicyRoleAssignment{PolicyID: p.ID, RoleID: developerRoleID}); err != nil {
		t.Fatalf("AssignToRole() error = %v", err)
	}

	if err := repo.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := repo.GetByID(ctx, p.ID); !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetByID() after Delete(), error = %v, want entity.ErrNotFound", err)
	}

	var ruleCount, assignmentCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM secret_policy_rules WHERE policy_id = $1`, p.ID).Scan(&ruleCount); err != nil {
		t.Fatalf("count secret_policy_rules: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM secret_policy_role_assignments WHERE policy_id = $1`, p.ID).Scan(&assignmentCount); err != nil {
		t.Fatalf("count secret_policy_role_assignments: %v", err)
	}
	if ruleCount != 0 {
		t.Errorf("secret_policy_rules rows remaining after Delete() = %d, want 0 (ON DELETE CASCADE)", ruleCount)
	}
	if assignmentCount != 0 {
		t.Errorf("secret_policy_role_assignments rows remaining after Delete() = %d, want 0 (ON DELETE CASCADE)", assignmentCount)
	}

	rules, err := repo.ListRulesForRoles(ctx, secretTestOrgID, []string{developerRoleID})
	if err != nil {
		t.Fatalf("ListRulesForRoles() after Delete(), error = %v", err)
	}
	for _, r := range rules {
		if r.PolicyID == p.ID {
			t.Error("ListRulesForRoles() still returned a rule from a deleted policy")
		}
	}
}

func TestSecretPolicyRepository_Delete_NotFound(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	err := repo.Delete(context.Background(), "00000000-0000-4000-9000-999999999998")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("Delete() for a nonexistent ID, error = %v, want entity.ErrNotFound", err)
	}
}

// migrations/000027's own backward-compatibility seed: a platform-wide
// "Full Access" policy (path "*", every action, allow) assigned to every
// role that already held secrets:read before path policies existed —
// Platform Administrator and Developer both qualify (migrations/000022,
// 000023, 000025). Verifying this against the real, migrated database is
// the only way to prove that migration's own data backfill actually ran
// as documented, not just that its SQL is syntactically plausible.
func TestSecretPolicyRepository_SeededFullAccessPolicy_CoversPreExistingRoles(t *testing.T) {
	db := connectForRegisterTest(t)
	repo := postgres.NewSecretPolicyRepository(db)
	ctx := context.Background()

	const fullAccessPolicyID = "00000000-0000-4000-9000-000000000200"
	ids, err := repo.ListAssignedRoleIDs(ctx, fullAccessPolicyID)
	if err != nil {
		t.Fatalf("ListAssignedRoleIDs(seeded Full Access policy) error = %v", err)
	}
	assigned := map[string]bool{}
	for _, id := range ids {
		assigned[id] = true
	}
	for _, roleID := range []string{platformAdminRoleID, developerRoleID} {
		if !assigned[roleID] {
			t.Errorf("seeded Full Access policy is not assigned to role %q, want it assigned (migrations/000027's own backward-compatibility backfill)", roleID)
		}
	}

	rules, err := repo.ListRulesForRoles(ctx, secretTestOrgID, []string{platformAdminRoleID})
	if err != nil {
		t.Fatalf("ListRulesForRoles(platformAdmin) error = %v", err)
	}
	var sawWildcard bool
	for _, r := range rules {
		if r.PolicyID == fullAccessPolicyID && r.PathPattern == "*" && r.Effect == entity.PolicyEffectAllow {
			sawWildcard = true
		}
	}
	if !sawWildcard {
		t.Error("Platform Administrator's resolved rules do not include the seeded wildcard allow rule")
	}
}
