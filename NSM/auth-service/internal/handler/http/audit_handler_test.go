package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/service"
)

// newTestAuditHandler wires an auditHandler against in-memory fakes,
// following secret_policy_handler_test.go's own established convention
// for this package exactly: no httptest server, no router, no middleware
// chain, and every request here carries NO claims in its context, so
// actorUserID(r) resolves to "" and every call is rejected by
// AuditService's own internal authorize() with entity.ErrForbidden before
// touching the fake repository. Full authorized-call coverage (a real
// admin actually listing real events) lives in test/e2e/audit_test.go.
func newTestAuditHandler(t *testing.T) *auditHandler {
	t.Helper()
	repo := mocks.NewFakeAuditLogRepository()
	rbacRepo := mocks.NewFakeRBACRepository()
	rbacSvc := service.NewRBACService(rbacRepo)
	auditTx := mocks.FakeAuditTx(repo)

	svc := service.NewAuditService(repo, rbacSvc, auditTx)
	return &auditHandler{svc: svc}
}

func auditListRequest(rawQuery string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/audit-logs?"+rawQuery, nil)
	req.Header.Set("X-Organization-Id", "org-1")
	return req
}

// --- malformed/invalid query parameters rejected before any service call ---

func TestAuditHandler_List_InvalidLimit(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest("limit=not-a-number"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec); code != "VALIDATION_ERROR" {
		t.Errorf("error code = %q, want VALIDATION_ERROR", code)
	}
}

func TestAuditHandler_List_LimitOutOfRange(t *testing.T) {
	for _, limit := range []string{"0", "-1", "101", "1000"} {
		t.Run(limit, func(t *testing.T) {
			h := newTestAuditHandler(t)
			rec := httptest.NewRecorder()
			h.list(rec, auditListRequest("limit="+limit))

			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("limit=%s: status = %d, want %d; body = %s", limit, rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
			}
		})
	}
}

func TestAuditHandler_List_InvalidOccurredAfter(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest("occurred_after=not-a-timestamp"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestAuditHandler_List_InvalidOccurredBefore(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest("occurred_before=2024-13-99"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestAuditHandler_List_OccurredAfterAfterOccurredBefore(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest("occurred_after=2026-06-01T00%3A00%3A00Z&occurred_before=2026-01-01T00%3A00%3A00Z"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestAuditHandler_List_InvalidActorType(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest("actor_type=not-a-real-actor-type"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestAuditHandler_List_InvalidResult(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest("result=maybe"))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

// --- defense-in-depth: no authenticated identity -> 403 ---

func TestAuditHandler_List_NoClaims_Returns403(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest(""))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if code := decodeErrorCode(t, rec); code != "FORBIDDEN" {
		t.Errorf("error code = %q, want FORBIDDEN", code)
	}
}

// --- no error response ever leaks internal detail ---

func TestAuditHandler_ErrorResponses_NeverLeakInternalDetail(t *testing.T) {
	h := newTestAuditHandler(t)
	rec := httptest.NewRecorder()
	h.list(rec, auditListRequest(""))

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"sql", "postgres", "goroutine", "panic", ".go:", "internal/"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("error response body unexpectedly contains %q: %s", forbidden, rec.Body.String())
		}
	}
}

// --- default limit applied when none is given ---

func TestAuditHandler_ParseAuditLogQuery_DefaultLimit(t *testing.T) {
	query, errs := parseAuditLogQuery(auditListRequest(""))
	if err := errs.Err(); err != nil {
		t.Fatalf("parseAuditLogQuery() unexpected error = %v", err)
	}
	if query.Limit != 20 {
		t.Errorf("Limit = %d, want the default of 20", query.Limit)
	}
}

func TestAuditHandler_ParseAuditLogQuery_AllFilters(t *testing.T) {
	req := auditListRequest("actor_type=user&actor_id=11111111-1111-4111-8111-111111111111&action=secret.read&resource_type=secret&resource_id=prod%2Fdb&result=denied&request_id=req-1&cursor=abc&limit=5")
	query, errs := parseAuditLogQuery(req)
	if err := errs.Err(); err != nil {
		t.Fatalf("parseAuditLogQuery() unexpected error = %v", err)
	}
	if query.ActorType == nil || *query.ActorType != "user" {
		t.Errorf("ActorType = %v, want %q", query.ActorType, "user")
	}
	if query.ActorID == nil || *query.ActorID != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("ActorID = %v, want %q", query.ActorID, "11111111-1111-4111-8111-111111111111")
	}
	if query.Action == nil || *query.Action != "secret.read" {
		t.Errorf("Action = %v, want %q", query.Action, "secret.read")
	}
	if query.ResourceType == nil || *query.ResourceType != "secret" {
		t.Errorf("ResourceType = %v, want %q", query.ResourceType, "secret")
	}
	if query.ResourceID == nil || *query.ResourceID != "prod/db" {
		t.Errorf("ResourceID = %v, want %q", query.ResourceID, "prod/db")
	}
	if query.Result == nil || *query.Result != "denied" {
		t.Errorf("Result = %v, want %q", query.Result, "denied")
	}
	if query.RequestID == nil || *query.RequestID != "req-1" {
		t.Errorf("RequestID = %v, want %q", query.RequestID, "req-1")
	}
	if query.Cursor == nil || *query.Cursor != "abc" {
		t.Errorf("Cursor = %v, want %q", query.Cursor, "abc")
	}
	if query.Limit != 5 {
		t.Errorf("Limit = %d, want 5", query.Limit)
	}
	if err := query.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a well-formed query", err)
	}
}
