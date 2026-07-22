package gateway_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/policy"
)

func mintJWT(t *testing.T, kid string, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	sig := ed25519.Sign(key, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// ZT-2: with an OIDC verifier wired, the access proxy resolves the USER identity from a verified
// bearer token (SSO) layered on the mTLS device cert. A valid token's role authorizes; a missing
// token is 401; an invalid token is 403 — and the upstream is never reached without a valid token.
func TestAccessProxyOIDCIdentity(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups",
		map[string]crypto.PublicKey{"k1": edPub})
	if err != nil {
		t.Fatal(err)
	}

	up, hit := accessUpstream(t)
	// Authorize the finance role — the role comes from the TOKEN's groups claim (ZT-2).
	pol, err := policy.New(nil, "oidc", "1", `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"finance","confidence":0.9} if { input.context.role == "finance" }
decision := {"action":"BLOCK","reason":"deny","confidence":0.9} if { input.context.role != "finance" }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	ap.SetOIDCVerifier(verifier)

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)
	// The DEVICE cert (mTLS) is still required; its group is irrelevant now — identity is the token.
	client := accessClient(ca.clientCert(t, "device-01", "device"), ca.pool)

	get := func(authz string) int {
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// A valid finance token → ALLOWED, upstream reached.
	tok := mintJWT(t, "k1", edPriv, map[string]any{
		"iss": "https://issuer.example", "aud": "openshield-gateway", "sub": "alice@corp",
		"groups": []string{"finance"}, "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix()})
	if code := get("Bearer " + tok); code != http.StatusOK || !hit.Load() {
		t.Errorf("valid token = %d (hit %v), want 200 + upstream reached", code, hit.Load())
	}

	// No token → 401, upstream not reached.
	hit.Store(false)
	if code := get(""); code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", code)
	}
	// A tampered token → 403, upstream not reached.
	if code := get("Bearer " + tok + "x"); code != http.StatusForbidden {
		t.Errorf("tampered token = %d, want 403", code)
	}
	if hit.Load() {
		t.Error("the upstream was reached without a valid token")
	}
}
