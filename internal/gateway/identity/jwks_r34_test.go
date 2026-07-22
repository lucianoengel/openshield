package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

// TestJWKSRejectsPlaintextURL (R34-3): a non-loopback http:// JWKS url is refused at
// construction — a plaintext JWKS fetch is a key-injection / auth-bypass vector.
func TestJWKSRejectsPlaintextURL(t *testing.T) {
	if _, err := identity.NewJWKSRefresher("http://idp.example.com/keys", time.Hour); err == nil {
		t.Fatal("a plaintext (http) remote JWKS url must be rejected (R34-3)")
	}
	// https is accepted.
	if _, err := identity.NewJWKSRefresher("https://idp.example.com/keys", time.Hour); err != nil {
		t.Fatalf("an https JWKS url should be accepted: %v", err)
	}
	// Loopback http is allowed (no MITM risk; dev/tests).
	if _, err := identity.NewJWKSRefresher("http://127.0.0.1:8080/keys", time.Hour); err != nil {
		t.Fatalf("a loopback http JWKS url should be allowed: %v", err)
	}
}

// TestJWKSBacksOffOnFailure (R34-3): a JWKS endpoint that is DOWN must not be hit
// once per kid-miss trigger — after a failed fetch the backoff grows, so a flood of
// unknown-kid triggers drives far fewer fetches than triggers.
func TestJWKSBacksOffOnFailure(t *testing.T) {
	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable) // always fails
	}))
	defer srv.Close()

	ref, err := identity.NewJWKSRefresher(srv.URL, time.Hour) // long interval: only triggers drive fetches
	if err != nil {
		t.Fatal(err)
	}
	ref = ref.WithMinGap(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ref.Start(ctx)
	time.Sleep(10 * time.Millisecond) // let the prime fetch happen (1 fetch)

	// Hammer with 200 unknown-kid lookups over ~100ms. Without backoff this would
	// drive ~1 fetch per 20ms window (≈5+); with exponential backoff after the first
	// failures it drives only a couple.
	for i := 0; i < 200; i++ {
		ref.KeyFor("unknown-kid")
		time.Sleep(500 * time.Microsecond)
	}
	time.Sleep(20 * time.Millisecond)

	if n := fetches.Load(); n > 4 {
		t.Fatalf("JWKS was fetched %d times under a flood against a DOWN endpoint — backoff not working (R34-3)", n)
	}
}
