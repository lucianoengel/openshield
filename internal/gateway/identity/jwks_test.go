package identity_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
)

func rsaJWK(kid string, k *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

func edJWK(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func jwksVerifier(t *testing.T, ref *identity.JWKSRefresher) *identity.OIDCVerifier {
	t.Helper()
	// A dummy static key satisfies the "at least one key" constructor check; the key SOURCE is then
	// replaced by the refresher.
	_, dummy, _ := ed25519.GenerateKey(rand.Reader)
	v, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups",
		map[string]crypto.PublicKey{"dummy": dummy.Public()})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	return v.SetKeySource(ref.KeyFor).WithClock(func() time.Time { return now })
}

func waitSnapshot(t *testing.T, ref *identity.JWKSRefresher, kid string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := ref.KeyFor(kid); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("key %q never appeared in the JWKS snapshot", kid)
}

// ZT-2b: the refresher fetches JWKS, a token signed by a fetched key verifies, a ROTATED key is picked
// up by a background refresh (no restart), and when the endpoint FAILS the last-good key still serves
// (serve-stale) — an RSA and an Ed25519 key both round-trip through JWK parsing.
func TestJWKSRotationAndServeStale(t *testing.T) {
	rsa1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa2, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	var mu sync.Mutex
	serve := "v1" // v1 = {rsa1, ed1}; v2 = {rsa2, ed1}
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		s, f := serve, fail
		mu.Unlock()
		if f {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		keys := []map[string]any{edJWK("ed1", edPub)}
		if s == "v1" {
			keys = append(keys, rsaJWK("rsa1", &rsa1.PublicKey))
		} else {
			keys = append(keys, rsaJWK("rsa2", &rsa2.PublicKey))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer srv.Close()

	ref := identity.NewJWKSRefresher(srv.URL, 40*time.Millisecond).WithMinGap(10 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ref.Start(ctx)

	waitSnapshot(t, ref, "rsa1")
	v := jwksVerifier(t, ref)
	now := time.Unix(1_700_000_000, 0)

	// A token signed by the fetched RSA key verifies; so does one signed by the fetched Ed25519 key.
	if _, err := v.Verify(signJWT(t, "RS256", "rsa1", rsa1, baseClaims(now))); err != nil {
		t.Fatalf("RSA token via JWKS rejected: %v", err)
	}
	if _, err := v.Verify(signJWT(t, "EdDSA", "ed1", edPriv, baseClaims(now))); err != nil {
		t.Fatalf("Ed25519 token via JWKS rejected: %v", err)
	}

	// ROTATION: the provider rotates to rsa2. A background refresh picks it up (no restart).
	mu.Lock()
	serve = "v2"
	mu.Unlock()
	waitSnapshot(t, ref, "rsa2")
	if _, err := v.Verify(signJWT(t, "RS256", "rsa2", rsa2, baseClaims(now))); err != nil {
		t.Fatalf("rotated RSA token rejected — the refresh did not pick up the new key: %v", err)
	}

	// SERVE-STALE: the endpoint goes down; the last-good key (rsa2) still resolves.
	mu.Lock()
	fail = true
	mu.Unlock()
	time.Sleep(150 * time.Millisecond) // several failed refresh attempts
	if _, ok := ref.KeyFor("rsa2"); !ok {
		t.Error("serve-stale failed: rsa2 not resolvable after the JWKS endpoint went down")
	}
}

// ZT-2b: KeyFor NEVER fetches — the token-verification path is HTTP-free. A refresher that is not
// started, whose snapshot is empty, resolves nothing AND makes no request to the JWKS endpoint.
func TestJWKSKeyForNeverFetches(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	}))
	defer srv.Close()

	ref := identity.NewJWKSRefresher(srv.URL, time.Hour) // not started — no background fetch
	for i := 0; i < 100; i++ {
		if _, ok := ref.KeyFor("any-kid"); ok {
			t.Fatal("KeyFor resolved a key from an unprimed snapshot")
		}
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("KeyFor issued %d HTTP fetch(es) — the verification path MUST be HTTP-free", got)
	}
}

// ZT-2b: a kid-miss triggers a refresh but it is RATE-LIMITED — a burst of unknown-kid lookups does not
// drive a burst of fetches at the identity provider.
func TestJWKSKidMissRateLimited(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{edJWK("ed1", edPub)}})
	}))
	defer srv.Close()

	// Long interval (no periodic refresh during the test) + a large min-gap (rate limit).
	ref := identity.NewJWKSRefresher(srv.URL, time.Hour).WithMinGap(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ref.Start(ctx)
	waitSnapshot(t, ref, "ed1") // one fetch: the immediate prime

	primed := atomic.LoadInt32(&hits)
	// A burst of unknown-kid lookups: each signals a refresh, but the min-gap rate-limits them.
	for i := 0; i < 200; i++ {
		_, _ = ref.KeyFor("unknown-kid")
	}
	time.Sleep(200 * time.Millisecond)
	if extra := atomic.LoadInt32(&hits) - primed; extra > 1 {
		t.Errorf("a burst of 200 unknown-kid lookups drove %d extra fetches — the kid-miss refresh is not rate-limited", extra)
	}
}
