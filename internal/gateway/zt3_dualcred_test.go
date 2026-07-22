package gateway_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/policy"
)

// ZT-3: dual credential — the USER identity comes from the OIDC token, the DEVICE posture from the
// client CERTIFICATE. A policy requiring a finance role AND a compliant device authorizes only when
// BOTH hold. Posture is keyed by the DEVICE (not the user): publishing posture for the user's
// subject does NOT satisfy the device requirement — a valid user on an unattested device is denied.
func TestAccessProxyDualCredential(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups",
		map[string]crypto.PublicKey{"k1": edPub})
	if err != nil {
		t.Fatal(err)
	}

	up, hit := accessUpstream(t)
	// Require BOTH a finance user (from the token) AND a compliant device (from the cert posture).
	pol, err := policy.New(nil, "zt3", "1", `package openshield
import rego.v1
ok if { input.context.role == "finance"; input.context.device_posture.compliant }
decision := {"action":"ALLOW","reason":"user+device","confidence":0.9} if { ok }
decision := {"action":"BLOCK","reason":"deny","confidence":0.9} if { not ok }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	ap.SetOIDCVerifier(verifier)
	ps := gateway.NewPostureStore()
	ap.SetPostureStore(ps)

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)
	deviceCert := ca.clientCert(t, "device-42", "client")
	client := accessClient(deviceCert, ca.pool)

	tok := mintJWT(t, "k1", edPriv, map[string]any{
		"iss": "https://issuer.example", "aud": "openshield-gateway", "sub": "alice@corp",
		"groups": []string{"finance"}, "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix()})

	get := func() int {
		req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// The user's pseudonym (what the token resolves to) and the device's pseudonym (the cert).
	userID, err := verifier.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	deviceSubject := subjectOf(t, deviceCert)

	// Valid finance token but NO device posture → DENIED (dual-cred: valid user, unattested device).
	hit.Store(false)
	if code := get(); code != http.StatusForbidden {
		t.Errorf("finance user on unattested device = %d, want 403 (device posture required)", code)
	}

	// Publish posture for the USER subject (WRONG key) → still DENIED: posture is device-keyed.
	ps.Set(userID.Subject, core.DevicePosture{Compliant: true})
	if code := get(); code != http.StatusForbidden {
		t.Errorf("posture published for the USER (not the device) = %d, want 403 — posture must be device-keyed", code)
	}
	if hit.Load() {
		t.Error("the upstream was reached without device posture")
	}

	// Publish COMPLIANT posture for the DEVICE → both credentials satisfied → ALLOWED.
	ps.Set(deviceSubject, core.DevicePosture{Compliant: true})
	if code := get(); code != http.StatusOK || !hit.Load() {
		t.Errorf("finance user on a compliant device = %d (hit %v), want 200 + reached", code, hit.Load())
	}
}
