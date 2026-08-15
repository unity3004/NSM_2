package service

import (
	"errors"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
)

const (
	auditTestOrgID    = "org-audit-1"
	auditAdminID      = "user-audit-admin"
	auditNobodyID     = "user-audit-nobody"
	permAuditReadTest = "audit:read"
)

type testAuditEnv struct {
	svc   *AuditService
	repo  *mocks.FakeAuditLogRepository
	rbac  *mocks.FakeRBACRepository
	audit *mocks.FakeAuditLogRepository
}

// newTestAuditEnv wires an AuditService against one shared
// FakeAuditLogRepository used both as the thing being read (repo) and the
// thing admin.audit.read writes get appended to (audit) — the same
// single-table reality postgres.NewAuditLogRepository(db) has in
// production, where AuditService's own read repository and the AuditTx
// closure's write repository are two Go values over the identical table.
func newTestAuditEnv(t *testing.T) *testAuditEnv {
	t.Helper()
	repo := mocks.NewFakeAuditLogRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := NewRBACService(rbacRepo)
	auditTx := mocks.FakeAuditTx(repo)

	rbacRepo.Grant(auditAdminID, permAuditReadTest)

	svc := NewAuditService(repo, rbacSvc, auditTx)
	return &testAuditEnv{svc: svc, repo: repo, rbac: rbacRepo, audit: repo}
}

func seedAuditEntry(t *testing.T, env *testAuditEnv, action string, result entity.AuditResult, occurredAt time.Time) *entity.AuditLogEntry {
	t.Helper()
	e := &entity.AuditLogEntry{
		OrganizationID: strPtr(auditTestOrgID),
		ActorType:      entity.AuditActorUser,
		ActorID:        strPtr("user-x"),
		Action:         action,
		ResourceType:   strPtr("secret"),
		Result:         result,
		OccurredAt:     occurredAt,
	}
	if err := env.repo.Append(t.Context(), e); err != nil {
		t.Fatalf("seed Append(%q): %v", action, err)
	}
	// Append (real and fake) sets OccurredAt itself; force the caller's
	// intended value back so tests can control ordering deterministically.
	e.OccurredAt = occurredAt
	return e
}

// --- 15/19 (objective's own security test list): unauthorized users
// cannot retrieve audit logs; admin can ---

func TestAuditService_ListAuditLogs_RequiresPermission(t *testing.T) {
	env := newTestAuditEnv(t)
	_, err := env.svc.ListAuditLogs(t.Context(), auditNobodyID, auditTestOrgID, repository.AuditLogFilter{}, "")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ListAuditLogs() without audit:read, error = %v, want entity.ErrForbidden", err)
	}
}

func TestAuditService_ListAuditLogs_UnauthenticatedDenied(t *testing.T) {
	env := newTestAuditEnv(t)
	_, err := env.svc.ListAuditLogs(t.Context(), "", auditTestOrgID, repository.AuditLogFilter{}, "")
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("ListAuditLogs() with no actor, error = %v, want entity.ErrForbidden", err)
	}
}

func TestAuditService_ListAuditLogs_AdminCanList(t *testing.T) {
	env := newTestAuditEnv(t)
	seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, time.Now())

	page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{}, "203.0.113.10")
	if err != nil {
		t.Fatalf("ListAuditLogs() error = %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Action != "secret.read" {
		t.Errorf("Entries = %+v, want one secret.read entry", page.Entries)
	}
}

// --- GetAuditLog: single-event lookup, GET /v1/audit-logs/{id} ---

func TestAuditService_GetAuditLog_AdminCanFetchOwnOrgEvent(t *testing.T) {
	env := newTestAuditEnv(t)
	seeded := seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, time.Now())

	got, err := env.svc.GetAuditLog(t.Context(), auditAdminID, auditTestOrgID, seeded.ID)
	if err != nil {
		t.Fatalf("GetAuditLog() error = %v", err)
	}
	if got.Action != "secret.read" {
		t.Errorf("Action = %q, want %q", got.Action, "secret.read")
	}
}

func TestAuditService_GetAuditLog_RequiresPermission(t *testing.T) {
	env := newTestAuditEnv(t)
	seeded := seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, time.Now())

	_, err := env.svc.GetAuditLog(t.Context(), auditNobodyID, auditTestOrgID, seeded.ID)
	if !errors.Is(err, entity.ErrForbidden) {
		t.Errorf("GetAuditLog() without audit:read, error = %v, want entity.ErrForbidden", err)
	}
}

// TestAuditService_GetAuditLog_CrossOrganizationReportsNotFound is the
// security-critical property this endpoint exists to enforce: an event
// ID is a small, sequential, guessable integer (BIGSERIAL) — an admin in
// one organization must not be able to read a different organization's
// event merely by incrementing the ID in the URL. Reported as
// ErrNotFound, never ErrForbidden, so the lookup itself can't be used to
// confirm a given ID belongs to someone else's organization at all — the
// same anti-enumeration posture GetAuditLog's own doc comment describes.
func TestAuditService_GetAuditLog_CrossOrganizationReportsNotFound(t *testing.T) {
	env := newTestAuditEnv(t)
	e := &entity.AuditLogEntry{
		OrganizationID: strPtr("some-other-org"),
		ActorType:      entity.AuditActorUser,
		Action:         "secret.read",
		Result:         entity.AuditResultSuccess,
	}
	if err := env.repo.Append(t.Context(), e); err != nil {
		t.Fatalf("seed Append: %v", err)
	}

	_, err := env.svc.GetAuditLog(t.Context(), auditAdminID, auditTestOrgID, e.ID)
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetAuditLog() for another organization's event, error = %v, want entity.ErrNotFound", err)
	}
}

func TestAuditService_GetAuditLog_UnknownIDReportsNotFound(t *testing.T) {
	env := newTestAuditEnv(t)
	_, err := env.svc.GetAuditLog(t.Context(), auditAdminID, auditTestOrgID, "does-not-exist")
	if !errors.Is(err, entity.ErrNotFound) {
		t.Errorf("GetAuditLog() for an unknown ID, error = %v, want entity.ErrNotFound", err)
	}
}

// TestAuditService_ListAuditLogs_CountsReflectFullFilteredSetNotOnePage
// is the Audit Explorer summary cards' own regression test: Counts must
// total every matching row, not just the one page Entries returns — the
// whole reason CountByResult is a separate, unpaginated query rather
// than a client-side tally of Entries (see AuditLogPage.Counts' own doc
// comment).
func TestAuditService_ListAuditLogs_CountsReflectFullFilteredSetNotOnePage(t *testing.T) {
	env := newTestAuditEnv(t)
	now := time.Now()
	seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, now)
	seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, now.Add(-time.Minute))
	seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, now.Add(-2*time.Minute))
	seedAuditEntry(t, env, "user.login", entity.AuditResultFailure, now.Add(-3*time.Minute))
	seedAuditEntry(t, env, "authorization.denied", entity.AuditResultDenied, now.Add(-4*time.Minute))

	page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Limit: 2}, "203.0.113.10")
	if err != nil {
		t.Fatalf("ListAuditLogs() error = %v", err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("Entries = %d, want exactly 2 (the requested page size)", len(page.Entries))
	}
	if page.Counts[entity.AuditResultSuccess] != 3 {
		t.Errorf("Counts[success] = %d, want 3 (all matching rows, not just this page)", page.Counts[entity.AuditResultSuccess])
	}
	if page.Counts[entity.AuditResultFailure] != 1 {
		t.Errorf("Counts[failure] = %d, want 1", page.Counts[entity.AuditResultFailure])
	}
	if page.Counts[entity.AuditResultDenied] != 1 {
		t.Errorf("Counts[denied] = %d, want 1", page.Counts[entity.AuditResultDenied])
	}
}

// --- 10 (objective's own list): audit access is itself audited ---

func TestAuditService_ListAuditLogs_RecordsAdminAuditRead(t *testing.T) {
	env := newTestAuditEnv(t)

	if _, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{}, "203.0.113.20"); err != nil {
		t.Fatalf("ListAuditLogs() error = %v", err)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action != "admin.audit.read" {
			continue
		}
		found = true
		if e.ActorID == nil || *e.ActorID != auditAdminID {
			t.Errorf("ActorID = %v, want %q", e.ActorID, auditAdminID)
		}
		if e.Result != entity.AuditResultSuccess {
			t.Errorf("Result = %q, want success", e.Result)
		}
		if e.IPAddress == nil || *e.IPAddress != "203.0.113.20" {
			t.Errorf("IPAddress = %v, want 203.0.113.20", e.IPAddress)
		}
	}
	if !found {
		t.Error("no admin.audit.read audit entry was recorded for a successful list")
	}
}

func TestAuditService_ListAuditLogs_DeniedAccessDoesNotRecordAdminAuditRead(t *testing.T) {
	env := newTestAuditEnv(t)
	_, _ = env.svc.ListAuditLogs(t.Context(), auditNobodyID, auditTestOrgID, repository.AuditLogFilter{}, "")

	for _, e := range env.audit.Entries {
		if e.Action == "admin.audit.read" {
			t.Error("admin.audit.read was recorded even though ListAuditLogs was denied — a denied read is not itself \"access\" to audit\n")
		}
	}
}

// --- filtering ---

func TestAuditService_ListAuditLogs_FiltersByAction(t *testing.T) {
	env := newTestAuditEnv(t)
	seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, time.Now())
	seedAuditEntry(t, env, "secret.deleted", entity.AuditResultSuccess, time.Now())

	action := "secret.deleted"
	page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Action: &action}, "")
	if err != nil {
		t.Fatalf("ListAuditLogs() error = %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Action != "secret.deleted" {
		t.Errorf("Entries = %+v, want exactly one secret.deleted entry", page.Entries)
	}
}

// TestAuditService_ListAuditLogs_ResourceIDFilterAlsoMatchesMetadataPath is
// the "search by resource ID/path" regression test: a secret/lease audit
// row's own resource_id is an opaque UUID, never the human-readable path
// an operator actually knows and searches for — that only lives in
// Metadata["path"] (secrets) or Metadata["resource_path"] (leases). The
// filter must match either, not just the opaque ID, or a path search
// silently returns nothing even though a matching row genuinely exists.
func TestAuditService_ListAuditLogs_ResourceIDFilterAlsoMatchesMetadataPath(t *testing.T) {
	env := newTestAuditEnv(t)
	secretEvent := &entity.AuditLogEntry{
		OrganizationID: strPtr(auditTestOrgID),
		ActorType:      entity.AuditActorUser,
		Action:         "secret.created",
		ResourceType:   strPtr("secret"),
		ResourceID:     strPtr("11111111-1111-1111-1111-111111111111"),
		Result:         entity.AuditResultSuccess,
		Metadata:       map[string]any{"path": "prod/db/password"},
	}
	if err := env.repo.Append(t.Context(), secretEvent); err != nil {
		t.Fatalf("seed secret event: %v", err)
	}
	leaseEvent := &entity.AuditLogEntry{
		OrganizationID: strPtr(auditTestOrgID),
		ActorType:      entity.AuditActorUser,
		Action:         "lease.created",
		ResourceType:   strPtr("lease"),
		ResourceID:     strPtr("22222222-2222-2222-2222-222222222222"),
		Result:         entity.AuditResultSuccess,
		Metadata:       map[string]any{"resource_path": "infra/postgres/demo"},
	}
	if err := env.repo.Append(t.Context(), leaseEvent); err != nil {
		t.Fatalf("seed lease event: %v", err)
	}

	t.Run("matches by the opaque resource_id itself", func(t *testing.T) {
		id := "11111111-1111-1111-1111-111111111111"
		page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{ResourceID: &id}, "")
		if err != nil {
			t.Fatalf("ListAuditLogs() error = %v", err)
		}
		if len(page.Entries) != 1 || page.Entries[0].Action != "secret.created" {
			t.Errorf("Entries = %+v, want exactly the secret.created entry", page.Entries)
		}
	})

	t.Run("matches by the secret's Metadata path", func(t *testing.T) {
		path := "prod/db/password"
		page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{ResourceID: &path}, "")
		if err != nil {
			t.Fatalf("ListAuditLogs() error = %v", err)
		}
		if len(page.Entries) != 1 || page.Entries[0].Action != "secret.created" {
			t.Errorf("Entries = %+v, want exactly the secret.created entry, found by its path", page.Entries)
		}
	})

	t.Run("matches by the lease's Metadata resource_path", func(t *testing.T) {
		path := "infra/postgres/demo"
		page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{ResourceID: &path}, "")
		if err != nil {
			t.Fatalf("ListAuditLogs() error = %v", err)
		}
		if len(page.Entries) != 1 || page.Entries[0].Action != "lease.created" {
			t.Errorf("Entries = %+v, want exactly the lease.created entry, found by its resource_path", page.Entries)
		}
	})

	t.Run("no match for an unrelated value", func(t *testing.T) {
		bogus := "does/not/exist"
		page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{ResourceID: &bogus}, "")
		if err != nil {
			t.Fatalf("ListAuditLogs() error = %v", err)
		}
		if len(page.Entries) != 0 {
			t.Errorf("Entries = %+v, want none", page.Entries)
		}
	})
}

func TestAuditService_ListAuditLogs_FiltersByResult(t *testing.T) {
	env := newTestAuditEnv(t)
	seedAuditEntry(t, env, "secret.access_denied", entity.AuditResultDenied, time.Now())
	seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, time.Now())

	denied := entity.AuditResultDenied
	page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Result: &denied}, "")
	if err != nil {
		t.Fatalf("ListAuditLogs() error = %v", err)
	}
	if len(page.Entries) != 1 || page.Entries[0].Result != entity.AuditResultDenied {
		t.Errorf("Entries = %+v, want exactly one denied entry", page.Entries)
	}
}

// --- 16/17 (objective's own list): pagination and filters work together,
// deterministically ---

func TestAuditService_ListAuditLogs_Pagination(t *testing.T) {
	env := newTestAuditEnv(t)
	// auditTx: nil for this service instance specifically — ListAuditLogs
	// itself best-effort records admin.audit.read on every call (see
	// recordAuditAccess), which would otherwise append a fresh "now"-
	// timestamped row into this same org's log on every page fetch below
	// and throw off the exact page-boundary/exact-count assertions this
	// test makes. That self-audit behavior is covered on its own by
	// TestAuditService_ListAuditLogs_RecordsAdminAuditRead above; this
	// test isolates pure pagination mechanics from it.
	svc := NewAuditService(env.repo, NewRBACService(env.rbac), nil)

	base := time.Now()
	// Oldest first insertion, but each with a distinct, increasing
	// timestamp so DESC ordering is unambiguous regardless of the fake's
	// tie-breaking rule.
	for i := 0; i < 5; i++ {
		seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, base.Add(time.Duration(i)*time.Second))
	}

	page1, err := svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Limit: 2}, "")
	if err != nil {
		t.Fatalf("page 1: ListAuditLogs() error = %v", err)
	}
	if len(page1.Entries) != 2 || !page1.HasMore || page1.NextCursor == "" {
		t.Fatalf("page 1 = %+v, want 2 entries, HasMore=true, a non-empty cursor", page1)
	}

	page2, err := svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Limit: 2, Cursor: &page1.NextCursor}, "")
	if err != nil {
		t.Fatalf("page 2: ListAuditLogs() error = %v", err)
	}
	if len(page2.Entries) != 2 || !page2.HasMore {
		t.Fatalf("page 2 = %+v, want 2 entries, HasMore=true", page2)
	}

	page3, err := svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Limit: 2, Cursor: &page2.NextCursor}, "")
	if err != nil {
		t.Fatalf("page 3: ListAuditLogs() error = %v", err)
	}
	if len(page3.Entries) != 1 || page3.HasMore {
		t.Fatalf("page 3 = %+v, want exactly 1 entry, HasMore=false (5 total, 2+2+1)", page3)
	}

	// No overlap and no gaps across all three pages.
	seen := map[string]bool{}
	for _, page := range [][]*entity.AuditLogEntry{page1.Entries, page2.Entries, page3.Entries} {
		for _, e := range page {
			if seen[e.ID] {
				t.Errorf("entry %s appeared on more than one page", e.ID)
			}
			seen[e.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Errorf("saw %d distinct entries across all pages, want 5", len(seen))
	}
}

func TestAuditService_ListAuditLogs_LimitClamped(t *testing.T) {
	env := newTestAuditEnv(t)
	for i := 0; i < 3; i++ {
		seedAuditEntry(t, env, "secret.read", entity.AuditResultSuccess, time.Now().Add(time.Duration(i)*time.Second))
	}
	// A negative/zero limit must not be treated as "unbounded" — it
	// clamps to the same default (20) the repository itself clamps to.
	page, err := env.svc.ListAuditLogs(t.Context(), auditAdminID, auditTestOrgID, repository.AuditLogFilter{Limit: -1}, "")
	if err != nil {
		t.Fatalf("ListAuditLogs() error = %v", err)
	}
	if len(page.Entries) != 3 {
		t.Errorf("Entries = %d, want 3 (all of them, well under the clamp)", len(page.Entries))
	}
}
