package util

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func reqFrom(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// setTestTrustedProxies sets the package-level trusted-proxy list for the
// duration of one test and restores it to empty afterward — this state
// is a deliberate package-level value (see SetTrustedProxies' own doc
// comment on why), so every test that touches it must clean up after
// itself or risk leaking configuration into an unrelated test that runs
// later in the same binary.
func setTestTrustedProxies(t *testing.T, cidrs []string) {
	t.Helper()
	SetTrustedProxies(cidrs)
	t.Cleanup(func() { SetTrustedProxies(nil) })
}

// --- default posture: no trusted proxies configured ---

func TestResolveClientIP_NoTrustedProxies_IgnoresForwardedHeaders(t *testing.T) {
	setTestTrustedProxies(t, nil)
	req := reqFrom("198.51.100.9:54321", map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "198.51.100.9" {
		t.Errorf("ResolveClientIP() = %q, want the peer address %q (X-Forwarded-For must be ignored with no trusted proxy configured)", got, "198.51.100.9")
	}
}

func TestResolveClientIP_NoTrustedProxies_IgnoresXRealIP(t *testing.T) {
	setTestTrustedProxies(t, nil)
	req := reqFrom("198.51.100.9:54321", map[string]string{"X-Real-IP": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "198.51.100.9" {
		t.Errorf("ResolveClientIP() = %q, want the peer address, X-Real-IP ignored", got)
	}
}

// --- the exact spoofing attack this function exists to prevent ---

func TestResolveClientIP_UntrustedPeer_CannotSpoofViaHeader(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.0.0.0/8"}) // configured, but the caller below isn't inside it
	req := reqFrom("198.51.100.9:54321", map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "198.51.100.9" {
		t.Errorf("ResolveClientIP() = %q, want the real peer %q — an untrusted direct caller must never have its own header trusted", got, "198.51.100.9")
	}
}

// --- trusted proxy: header is honored, correctly ---

func TestResolveClientIP_TrustedProxy_UsesForwardedFor(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.0.0.0/8"})
	req := reqFrom("10.1.2.3:54321", map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "203.0.113.1" {
		t.Errorf("ResolveClientIP() = %q, want %q (from a trusted proxy)", got, "203.0.113.1")
	}
}

func TestResolveClientIP_TrustedProxy_MultiHopChain_SkipsTrustedHops(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.0.0.0/8"})
	// client, then two trusted proxies in the chain (as XFF is
	// conventionally appended to, left to right) — the real client is the
	// leftmost, first-non-trusted entry when walked from the right.
	req := reqFrom("10.0.0.5:54321", map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.2, 10.0.0.5"})
	if got := ResolveClientIP(req); got != "203.0.113.1" {
		t.Errorf("ResolveClientIP() = %q, want %q (the first non-trusted hop from the right)", got, "203.0.113.1")
	}
}

func TestResolveClientIP_TrustedProxy_BareIPTrustedEntry(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.5.5.5"}) // a single bare IP, not a CIDR
	req := reqFrom("10.5.5.5:54321", map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "203.0.113.1" {
		t.Errorf("ResolveClientIP() = %q, want %q (a bare-IP trusted-proxy entry must work like a /32)", got, "203.0.113.1")
	}
}

func TestResolveClientIP_TrustedProxy_XRealIPFallback(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.0.0.0/8"})
	req := reqFrom("10.1.2.3:54321", map[string]string{"X-Real-IP": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "203.0.113.1" {
		t.Errorf("ResolveClientIP() = %q, want %q (X-Real-IP fallback when X-Forwarded-For is absent)", got, "203.0.113.1")
	}
}

func TestResolveClientIP_TrustedProxy_MalformedForwardedFor_FallsBackToPeer(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.0.0.0/8"})
	req := reqFrom("10.1.2.3:54321", map[string]string{"X-Forwarded-For": "not-an-ip-address"})
	if got := ResolveClientIP(req); got != "10.1.2.3" {
		t.Errorf("ResolveClientIP() = %q, want the peer address as a safe fallback for an unparseable header", got)
	}
}

func TestResolveClientIP_TrustedProxy_EveryHopTrusted_FallsBackToPeer(t *testing.T) {
	setTestTrustedProxies(t, []string{"10.0.0.0/8"})
	req := reqFrom("10.1.2.3:54321", map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"})
	if got := ResolveClientIP(req); got != "10.1.2.3" {
		t.Errorf("ResolveClientIP() = %q, want the peer address when every chain entry is itself trusted (no real client visible)", got)
	}
}

func TestSetTrustedProxies_MalformedEntrySkippedNotFatal(t *testing.T) {
	setTestTrustedProxies(t, []string{"not-a-cidr-or-ip", "10.0.0.0/8"})
	req := reqFrom("10.1.2.3:54321", map[string]string{"X-Forwarded-For": "203.0.113.1"})
	if got := ResolveClientIP(req); got != "203.0.113.1" {
		t.Errorf("ResolveClientIP() = %q, want %q — a malformed entry must not break the valid ones alongside it", got, "203.0.113.1")
	}
}
