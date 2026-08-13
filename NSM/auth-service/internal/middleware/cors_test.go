package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okHandler is the "protected handler" every test in this file wraps
// with CORS — it just reports whether it was actually invoked, so a test
// can distinguish "CORS blocked this at the browser level via a missing
// header" (the handler still runs — CORS never denies a same-origin or
// non-browser caller) from "CORS itself short-circuited the request"
// (only ever true for OPTIONS, see CORS's own doc comment).
func okHandler() (http.Handler, *bool) {
	called := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), &called
}

func TestCORS_AllowedOrigin_RealRequest_SetsHeadersAndInvokesHandler(t *testing.T) {
	handler, called := okHandler()
	mw := CORS([]string{"http://localhost:5173"})(handler)

	req := httptest.NewRequest(http.MethodGet, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:5173")
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want %q", got, "Origin")
	}
	if !*called {
		t.Error("the wrapped handler was never invoked for a real (non-OPTIONS) request")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestCORS_DisallowedOrigin_RealRequest_NoHeadersButHandlerStillRuns
// proves the requirement's own "disallowed origins are not granted
// access" case: the response carries no Access-Control-Allow-Origin at
// all, which is what makes a browser refuse to let the calling page's
// JavaScript read the response — CORS is enforced by the browser
// withholding the response from script, not by this server refusing to
// answer the request (a non-browser caller, or a same-origin page, was
// never CORS's problem to begin with).
func TestCORS_DisallowedOrigin_RealRequest_NoHeadersButHandlerStillRuns(t *testing.T) {
	handler, called := okHandler()
	mw := CORS([]string{"http://localhost:5173"})(handler)

	req := httptest.NewRequest(http.MethodGet, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (origin not in the allowed list)", got)
	}
	if !*called {
		t.Error("the wrapped handler was never invoked")
	}
}

func TestCORS_NoOriginHeader_NoCORSHeadersSet(t *testing.T) {
	handler, called := okHandler()
	mw := CORS([]string{"http://localhost:5173"})(handler)

	// A same-origin request, or a non-browser client (curl, another
	// backend service), never sends an Origin header at all — this must
	// never be treated as a match against an empty/unset allow-list
	// entry.
	req := httptest.NewRequest(http.MethodGet, "/v1/platform/status", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (no Origin header was sent)", got)
	}
	if !*called {
		t.Error("the wrapped handler was never invoked")
	}
}

// TestCORS_OPTIONS_AllowedOrigin_ReturnsHeadersAndNoContent is the
// requirement's own "OPTIONS preflight requests must receive the
// required CORS headers and a successful response" case.
func TestCORS_OPTIONS_AllowedOrigin_ReturnsHeadersAndNoContent(t *testing.T) {
	handler, called := okHandler()
	mw := CORS([]string{"http://localhost:5173"})(handler)

	req := httptest.NewRequest(http.MethodOptions, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:5173")
	}
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		if allow := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(allow, method) {
			t.Errorf("Access-Control-Allow-Methods = %q, want it to contain %q", allow, method)
		}
	}
	for _, header := range []string{"Authorization", "Content-Type"} {
		if allow := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(allow, header) {
			t.Errorf("Access-Control-Allow-Headers = %q, want it to contain %q", allow, header)
		}
	}
	if *called {
		t.Error("the wrapped handler was invoked for an OPTIONS preflight — it must be answered by CORS alone")
	}
}

// TestCORS_OPTIONS_DisallowedOrigin_StillNoContentButNoHeaders proves the
// preflight itself still gets a non-error status (204) — matching what
// the bug report observed — but a disallowed origin gets no
// Access-Control-Allow-Origin, which is what actually blocks the browser
// from proceeding to the real request.
func TestCORS_OPTIONS_DisallowedOrigin_StillNoContentButNoHeaders(t *testing.T) {
	handler, _ := okHandler()
	mw := CORS([]string{"http://localhost:5173"})(handler)

	req := httptest.NewRequest(http.MethodOptions, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

// TestCORS_NeverEchoesLiteralWildcard is the requirement's own "Do not
// use Access-Control-Allow-Origin: * if the application may use
// credentials" case: even when "*" is itself one of the configured
// allowed origins, the header value returned is always the concrete
// requesting Origin, never the literal string "*" — safe to combine with
// credentialed requests (cookies, or a stored bearer token sent via
// `credentials: "include"`) without opening access to every origin at
// once.
func TestCORS_NeverEchoesLiteralWildcard(t *testing.T) {
	handler, _ := okHandler()
	mw := CORS([]string{"*"})(handler)

	req := httptest.NewRequest(http.MethodGet, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the concrete origin %q, never a literal wildcard", got, "http://localhost:5173")
	}
}

func TestCORS_EmptyAllowedOrigins_NeverGrantsAccess(t *testing.T) {
	handler, called := okHandler()
	// The safe default (config.ServerConfig.AllowedOrigins' own zero
	// value) — a deployment that never configured this must fail closed,
	// not silently allow everything.
	mw := CORS(nil)(handler)

	req := httptest.NewRequest(http.MethodGet, "/v1/platform/status", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty when no origins are configured", got)
	}
	if !*called {
		t.Error("the wrapped handler was never invoked")
	}
}
