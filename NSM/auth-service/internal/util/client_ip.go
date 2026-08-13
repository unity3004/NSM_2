package util

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// trustedProxies holds the parsed CIDR ranges SetTrustedProxies was last
// called with — a package-level value, deliberately, for the same reason
// internal/logging's zap.L() fallback already is one: ResolveClientIP is
// called from both internal/handler/http and internal/middleware, two
// packages that must never import each other (see
// middleware/authorize.go's own doc comment on that constraint), and
// every request-handling call site already reaches this package already
// (util.Claims, util.RequestIDFromContext) — threading a trusted-proxy
// list through every handler struct's constructor instead would touch
// roughly a dozen files for a value that is fixed for the lifetime of one
// process, set exactly once, at startup, by the composition root
// (cmd/server/main.go / test/e2e/setup_test.go), the same "configure once
// near the edge, read everywhere" shape RequestID's own context value
// already follows one layer down.
var (
	trustedProxiesMu sync.RWMutex
	trustedProxies   []netip.Prefix
)

// SetTrustedProxies parses cidrs (e.g. "10.0.0.0/8", "172.16.0.0/12") and
// replaces the trusted-proxy list ResolveClientIP consults. Call this
// exactly once, at process startup, before serving any request — see
// config.ServerConfig.TrustedProxies' own doc comment for the security
// reasoning behind why an empty list (the default) is the only safe
// starting point. A malformed entry is skipped, not fatal: a typo in one
// CIDR should not prevent the server from starting with everything else
// correctly configured, and an empty resulting list still degrades to the
// safe "ignore every proxy header" behavior.
func SetTrustedProxies(cidrs []string) {
	parsed := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			// A bare IP ("10.0.0.5") is a common, legitimate shorthand for
			// "trust exactly this one address" — accepted as a /32 (or
			// /128 for IPv6) rather than rejected outright.
			if addr, addrErr := netip.ParseAddr(c); addrErr == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				parsed = append(parsed, netip.PrefixFrom(addr, bits))
			}
			continue
		}
		parsed = append(parsed, p)
	}
	trustedProxiesMu.Lock()
	trustedProxies = parsed
	trustedProxiesMu.Unlock()
}

func isTrustedProxy(addr netip.Addr) bool {
	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()
	for _, p := range trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ResolveClientIP is the one place this codebase decides "what IP is this
// request actually from" — used for rate-limit dimensions and audit
// IPAddress fields alike, replacing what were previously two independent,
// identically-vulnerable copies (handler/http/auth_handler.go's clientIP
// and middleware/authorize.go's clientIPMW): both blindly returned
// X-Forwarded-For's raw value with no check on who sent it, meaning any
// direct, unproxied client could set that header to an arbitrary string
// and have it trusted outright — trivially defeating IP-based rate
// limiting (rotate the header value per request to look like a fresh IP
// every time) or framing another address for a block (set X-Forwarded-For
// to a victim's IP).
//
// The fix: X-Forwarded-For/X-Real-IP are consulted at all only when the
// request's own direct TCP peer (r.RemoteAddr) is itself inside
// SetTrustedProxies' configured range — i.e., only when this deployment
// has explicitly declared "requests arriving directly from this address
// are my own reverse proxy, not a client." With no trusted proxies
// configured (the default), every request's client IP is r.RemoteAddr,
// full stop, regardless of what headers it carries — the only
// unconditionally safe behavior for a deployment that hasn't stated
// otherwise.
//
// When the peer *is* trusted, X-Forwarded-For is parsed as the standard
// comma-separated hop chain (client, proxy1, proxy2, ...) and walked from
// the right: each trusted-proxy hop is skipped, and the first entry that
// is *not* itself a trusted proxy is the answer — the real client,
// correctly resolved even through a chain of multiple trusted proxies,
// and never an attacker-controlled value spliced onto the front of the
// header by a client that reached the trusted proxy directly (a
// well-configured proxy overwrites or appends to this header rather than
// passing a client-supplied one through verbatim, but this function does
// not assume that — it only trusts hops it can itself verify are
// trusted). X-Real-IP is consulted only as a fallback when
// X-Forwarded-For is entirely absent, since it carries only one address
// and cannot express a multi-hop chain.
func ResolveClientIP(r *http.Request) string {
	peer := hostOnly(r.RemoteAddr)
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !isTrustedProxy(peerAddr) {
		return peer
	}

	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		hops := strings.Split(fwd, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(hops[i])
			addr, err := netip.ParseAddr(candidate)
			if err != nil {
				continue
			}
			if !isTrustedProxy(addr) {
				return candidate
			}
		}
		// Every hop in the chain was itself a trusted proxy (or
		// unparseable) — fall through to the real-IP header, then the
		// peer address, rather than returning an empty string.
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		if _, err := netip.ParseAddr(strings.TrimSpace(real)); err == nil {
			return strings.TrimSpace(real)
		}
	}
	return peer
}

func hostOnly(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
