package controlplane

import (
	"crypto/subtle"
	"net"
	"net/http"
)

// RequireBearerToken wraps a handler so it is served only to a request carrying the exact bearer
// token (PLAT-4b). The /metrics endpoint leaks fleet operational tempo (rejected/gapped-telemetry
// counts reveal replay-attempt reconnaissance), so exposing it beyond loopback should require auth.
// The comparison is constant-time so a token is not recoverable by timing.
func RequireBearerToken(token string, h http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "metrics require a bearer token", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// IsNonLoopbackBind reports whether a listen address exposes the endpoint BEYOND loopback — an
// unspecified host (":9090", "0.0.0.0:…", "[::]:…") binds all interfaces, and any non-loopback IP or
// a hostname is reachable off-host. A loopback bind (127.0.0.0/8, ::1, "localhost") is safe. Used to
// warn loudly when /metrics would be exposed without auth (PLAT-4b).
func IsNonLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // no port — treat the whole thing as the host
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return true // all interfaces
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // a hostname that isn't localhost — assume reachable off-host
	}
	return !ip.IsLoopback()
}
