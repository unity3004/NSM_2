package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

func allowHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func requestWithClaims(subject string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Request-Id", "req-test-authorize")
	ctx := withClaims(req.Context(), &util.Claims{Subject: subject})
	ctx = util.WithRequestID(ctx, "req-test-authorize")
	return req.WithContext(ctx)
}

// requestWithServiceAccountClaims mirrors requestWithClaims for a machine
// token — SessionID left empty, the same signal util.Claims.IsServiceAccount
// is built on (see that method's own doc comment).
func requestWithServiceAccountClaims(subject string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-Request-Id", "req-test-authorize")
	ctx := withClaims(req.Context(), &util.Claims{Subject: subject, SessionID: ""})
	ctx = util.WithRequestID(ctx, "req-test-authorize")
	return req.WithContext(ctx)
}

// --- allow / deny ---

func TestRequirePermission_Allowed(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacRepo.Grant("user-1", "secrets:read")
	rbac := service.NewRBACService(rbacRepo)

	handler := RequirePermission(rbac, nil, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithClaims("user-1"))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequirePermission_Denied(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbac := service.NewRBACService(rbacRepo)

	handler := RequirePermission(rbac, nil, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithClaims("user-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec.Body.Len() == 0 {
		t.Error("expected a JSON error body")
	}
}

func TestRequirePermission_NoClaims_Unauthenticated(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbac := service.NewRBACService(rbacRepo)

	handler := RequirePermission(rbac, nil, "secrets:read")(allowHandler())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// --- Sprint 4 Task 3: authorization.denied is recorded on every 403,
// regardless of which resource/permission the route names ---

func TestRequirePermission_Denied_RecordsAuthorizationDeniedEvent(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbac := service.NewRBACService(rbacRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	handler := RequirePermission(rbac, auditTx, "users:create")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithClaims("user-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	found := false
	for _, e := range audit.Entries {
		if e.Action != "authorization.denied" {
			continue
		}
		found = true
		if e.ActorID == nil || *e.ActorID != "user-1" {
			t.Errorf("ActorID = %v, want %q", e.ActorID, "user-1")
		}
		if e.ResourceType == nil || *e.ResourceType != "users" {
			t.Errorf("ResourceType = %v, want %q (the permission's resource segment)", e.ResourceType, "users")
		}
		if e.RequestID == nil || *e.RequestID != "req-test-authorize" {
			t.Errorf("RequestID = %v, want %q", e.RequestID, "req-test-authorize")
		}
		if perm, _ := e.Metadata["permission"].(string); perm != "users:create" {
			t.Errorf("Metadata[permission] = %v, want %q", e.Metadata["permission"], "users:create")
		}
	}
	if !found {
		t.Error("no authorization.denied audit entry was recorded")
	}
}

func TestRequirePermission_Allowed_DoesNotRecordAnything(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacRepo.Grant("user-1", "secrets:read")
	rbac := service.NewRBACService(rbacRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	handler := RequirePermission(rbac, auditTx, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithClaims("user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if len(audit.Entries) != 0 {
		t.Errorf("Entries = %v, want none — an allowed request is not this middleware's event to audit (see RequirePermission's own doc comment on authorization.allowed)", audit.Entries)
	}
}

func TestRequirePermission_NilAuditTx_StillDeniesCorrectly(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbac := service.NewRBACService(rbacRepo)

	handler := RequirePermission(rbac, nil, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithClaims("user-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d — a nil auditTx must not affect the authorization decision itself", rec.Code, http.StatusForbidden)
	}
}

// --- Sprint 5 Task 1: a service-account-issued token is checked against
// service_account_roles, never user_roles ---

func TestRequirePermission_ServiceAccount_Allowed(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacRepo.Grant("sa-1", "secrets:read")
	rbac := service.NewRBACService(rbacRepo)

	handler := RequirePermission(rbac, nil, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithServiceAccountClaims("sa-1"))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequirePermission_ServiceAccount_Denied(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbac := service.NewRBACService(rbacRepo)

	handler := RequirePermission(rbac, nil, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithServiceAccountClaims("sa-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestRequirePermission_Denied_ServiceAccount_RecordsActorTypeServiceAccount
// proves the audit entry a denied service-account request produces is
// attributed to AuditActorServiceAccount, not AuditActorUser — the same
// dispatch the permission check itself makes, kept in sync (see
// recordAuthorizationDenied's own doc comment).
func TestRequirePermission_Denied_ServiceAccount_RecordsActorTypeServiceAccount(t *testing.T) {
	rbacRepo := mocks.NewFakeRBACRepository()
	rbac := service.NewRBACService(rbacRepo)
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)

	handler := RequirePermission(rbac, auditTx, "secrets:read")(allowHandler())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithServiceAccountClaims("sa-1"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	found := false
	for _, e := range audit.Entries {
		if e.Action != "authorization.denied" {
			continue
		}
		found = true
		if e.ActorType != entity.AuditActorServiceAccount {
			t.Errorf("ActorType = %q, want %q", e.ActorType, entity.AuditActorServiceAccount)
		}
	}
	if !found {
		t.Error("no authorization.denied audit entry was recorded")
	}
}
