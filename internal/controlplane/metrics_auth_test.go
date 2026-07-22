package controlplane_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// PLAT-4b: the metrics endpoint requires the exact bearer token when wrapped — no token or a wrong
// token is 401, the right token reaches the handler.
func TestRequireBearerToken(t *testing.T) {
	reached := false
	h := controlplane.RequireBearerToken("s3cret", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		auth string
		code int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"s3cret", http.StatusUnauthorized}, // missing the "Bearer " scheme
		{"Bearer s3cret", http.StatusOK},
	}
	for _, c := range cases {
		reached = false
		req := httptest.NewRequest("GET", "/metrics", nil)
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != c.code {
			t.Errorf("auth %q = %d, want %d", c.auth, rr.Code, c.code)
		}
		if (rr.Code == http.StatusOK) != reached {
			t.Errorf("auth %q: handler reached=%v but code=%d", c.auth, reached, rr.Code)
		}
	}
}

// The non-loopback bind guard flags addresses reachable off-host and passes loopback ones.
func TestIsNonLoopbackBind(t *testing.T) {
	nonLoopback := []string{":9090", "0.0.0.0:9090", "[::]:9090", "192.168.1.5:9090", "metrics.internal:9090"}
	loopback := []string{"127.0.0.1:9090", "localhost:9090", "[::1]:9090", "127.0.0.5:9090"}
	for _, a := range nonLoopback {
		if !controlplane.IsNonLoopbackBind(a) {
			t.Errorf("%q flagged as loopback, want non-loopback (exposed)", a)
		}
	}
	for _, a := range loopback {
		if controlplane.IsNonLoopbackBind(a) {
			t.Errorf("%q flagged as non-loopback, want loopback (safe)", a)
		}
	}
}
