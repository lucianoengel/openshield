package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/posture"
	"github.com/lucianoengel/openshield/internal/pseudonym"
)

// publishRealPosture drives the REAL device-posture path: it builds a signed PostureUpdate with the
// production producer serializer (posture.Build) under the CANONICAL pseudonym of the agent identity,
// then verifies+stores it through a real PostureSubscriber whose roster is keyed by that same
// canonical derivation (loaded from a roster file, as deployed). It returns without ever calling
// store.Set directly — so a test that relies on it cannot pass by sharing the code's keying premise.
func publishRealPosture(t *testing.T, store *gateway.PostureStore, agentID string, r posture.Report) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rosterPath := filepath.Join(t.TempDir(), "roster")
	// The roster lists the human agent identity; the loader canonicalizes it (IDENT-1).
	if err := os.WriteFile(rosterPath, []byte(agentID+" "+base64.StdEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := gateway.LoadPostureRoster(rosterPath)
	if err != nil {
		t.Fatalf("load roster: %v", err)
	}
	sub := gateway.NewPostureSubscriber(store, resolver)
	data, err := posture.Build(pseudonym.Of(agentID), r, priv)
	if err != nil {
		t.Fatalf("build posture: %v", err)
	}
	if err := sub.Apply(data); err != nil {
		t.Fatalf("real posture apply (agent %q): %v", agentID, err)
	}
}

// IDENT-1: the device-posture chain works on the REAL path end to end. Posture is published through
// the real producer (posture.Build) under the canonical pseudonym of the agent identity, verified by
// the gateway against that agent's own enrolled key (roster keyed by the same derivation), stored,
// and then resolved by the access proxy from a DEVICE certificate whose CN is that agent identity —
// with NO test seeding the store under the key it later asserts. Before the fix the publisher keyed
// by the raw agent id, so this resolve missed and every compliant device read HasPosture=false.
func TestPostureChainRealPathEndToEnd(t *testing.T) {
	const agentID = "device-42"

	up, hit := accessUpstream(t)
	// Gate on has_posture ALONE (the tamper-lockout, D85): an attested device is trusted, an
	// unattested one is not — isolating the exact property IDENT-1 restores.
	pol, err := policy.New(context.Background(), "ident1", "1", `package openshield
import rego.v1
trusted if { input.context.role == "finance"; input.context.device_posture.has_posture }
decision := {"action":"ALLOW","reason":"attested device","confidence":0.9} if { trusted }
decision := {"action":"BLOCK","reason":"unattested device","confidence":0.9} if { not trusted }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	ps := gateway.NewPostureStore()
	ap.SetPostureStore(ps)

	// Populate posture ONLY through the real producer→subscriber→store path.
	publishRealPosture(t, ps, agentID, posture.Report{Compliant: true, DiskEncrypted: true, AgentPresent: true})

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)

	// The device certificate's CN is the agent identity (ADR-6). The subject the proxy derives from
	// it MUST equal the canonical pseudonym the producer published under — this is the join that was
	// broken. Assert it directly, then prove it through the served proxy.
	deviceCert := ca.clientCert(t, agentID, "finance")
	if got, want := subjectOf(t, deviceCert), pseudonym.Of(agentID); got != want {
		t.Fatalf("device cert subject %q != published posture key %q — the canonical join is broken", got, want)
	}
	client := accessClient(deviceCert, ca.pool)

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !hit.Load() {
		t.Errorf("compliant device (posture via the real chain) = %d (hit %v), want 200 + reached — "+
			"the posture chain is inert; IDENT-1 regressed", resp.StatusCode, hit.Load())
	}

	// A different device whose agent NEVER published posture → absent → 403 (the tamper-lockout still
	// holds; the fix did not turn the gate into allow-all).
	otherCert := ca.clientCert(t, "device-99", "finance")
	otherClient := accessClient(otherCert, ca.pool)
	resp2, err := otherClient.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("device with no published posture = %d, want 403 (unattested → denied)", resp2.StatusCode)
	}
}
