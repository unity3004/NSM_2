package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/util"
)

// newTestCORSRouter builds the real NewRouter — the same construction
// cmd/server/main.go uses — with only what's needed to exercise CORS end
// to end without panicking: every request this file sends is either an
// OPTIONS preflight (answered entirely by middleware.CORS, before the
// request ever reaches a route handler or its service dependencies — see
// that middleware's own doc comment) or GET /healthz (registered
// unconditionally, with no service dependency at all). No other route in
// this router is ever invoked by these tests, so leaving every
// RouterDeps service field at its zero value (nil) is deliberate, not an
// oversight.
func newTestCORSRouter(t *testing.T, allowedOrigins []string) http.Handler {
	t.Helper()
	return NewRouter(RouterDeps{
		TokenAuth:      util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute),
		AllowedOrigins: allowedOrigins,
		Logger:         zap.NewNop(),
	})
}

// TestRouterCORS_OPTIONS_PlatformStatus_AllowedOrigin is this bug
// report's own reproduction, run against the real router: OPTIONS
// /v1/platform/status from the configured frontend origin must return
// Access-Control-Allow-Origin and a successful (204) status — the two
// things the browser console error said were missing.
func TestRouterCORS_OPTIONS_PlatformStatus_AllowedOrigin(t *testing.T) {
	router := newTestCORSRouter(t, []string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodOptions, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:5173")
	}
}

// TestRouterCORS_OPTIONS_PlatformBootstrap_AllowedOrigin is the same
// proof for POST /v1/platform/bootstrap — the other endpoint this bug
// report named explicitly.
func TestRouterCORS_OPTIONS_PlatformBootstrap_AllowedOrigin(t *testing.T) {
	router := newTestCORSRouter(t, []string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodOptions, "/v1/platform/bootstrap", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:5173")
	}
}

// TestRouterCORS_OPTIONS_PlatformStatus_DisallowedOrigin proves the
// requirement's own "disallowed origins are not granted access" case
// against the real router, not just the isolated middleware.
func TestRouterCORS_OPTIONS_PlatformStatus_DisallowedOrigin(t *testing.T) {
	router := newTestCORSRouter(t, []string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodOptions, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}

// TestRouterCORS_GetHealthz_AllowedOrigin_ReceivesAccessControlHeader is
// the requirement's own generic "API requests from the allowed origin
// receive Access-Control-Allow-Origin" case, proven against a real,
// non-OPTIONS request that actually reaches a handler and returns
// 200 — GET /healthz needs no service dependencies, so it's the one
// route in this router safe to call for real without any fake/mock
// wiring (see newTestCORSRouter's own doc comment).
func TestRouterCORS_GetHealthz_AllowedOrigin_ReceivesAccessControlHeader(t *testing.T) {
	router := newTestCORSRouter(t, []string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:5173")
	}
}

func TestRouterCORS_GetHealthz_DisallowedOrigin_NoAccessControlHeader(t *testing.T) {
	router := newTestCORSRouter(t, []string{"http://localhost:5173"})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}
