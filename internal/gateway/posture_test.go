package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/posture"
)

// SEC-12: each posture update is verified against the REPORTING AGENT's OWN enrolled key (bound to
// the update's subject), so an agent holding only its own key cannot forge Compliant=true for a
// DIFFERENT agent — the shared-key agent-to-agent forgery SEC-1 left open. An unsigned/malformed/
// unknown-subject update is rejected.
func TestPostureSubscriberBindsSubjectToKey(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	// Roster: agent-A and agent-B each enrolled with their own key.
	roster := map[string]ed25519.PublicKey{"agent-A": pubA, "agent-B": pubB}
	store := gateway.NewPostureStore()
	sub := gateway.NewPostureSubscriber(store, func(subject string) (ed25519.PublicKey, bool) {
		k, ok := roster[subject]
		return k, ok
	})

	signPosture := func(signer ed25519.PrivateKey, subject string, compliant bool) []byte {
		payload, _ := proto.Marshal(&corev1.PostureUpdate{Subject: subject, Compliant: compliant, DiskEncrypted: true})
		data, _ := gateway.SignUpdate(payload, signer)
		return data
	}

	// A reports its OWN posture, signed with A's key → applied.
	if err := sub.Apply(signPosture(privA, "agent-A", true)); err != nil {
		t.Fatalf("agent-A's own signed posture was rejected: %v", err)
	}
	if dp, ok := store.Get("agent-A"); !ok || !dp.Compliant {
		t.Errorf("agent-A store = %+v/%v, want present + compliant", dp, ok)
	}

	// THE SEC-12 FIX: agent-A (holding only its own key) forges agent-B's Compliant=true — subject
	// says agent-B but the signature is A's. It MUST be rejected: it does not verify against B's key.
	if err := sub.Apply(signPosture(privA, "agent-B", true)); err == nil {
		t.Error("agent-A forged agent-B's posture — subject↔key binding is broken (agent-to-agent forgery)")
	}
	if _, ok := store.Get("agent-B"); ok {
		t.Error("a forged posture for agent-B reached the store")
	}
	// B reporting its own posture with B's key still works (proves it is not a blanket denial).
	if err := sub.Apply(signPosture(privB, "agent-B", true)); err != nil {
		t.Errorf("agent-B's own signed posture was rejected: %v", err)
	}

	// An unknown subject (not enrolled) → rejected (no key to verify against).
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := sub.Apply(signPosture(strangerPriv, "agent-Z", true)); err == nil {
		t.Error("posture for an unenrolled subject was accepted")
	}
	// Unsigned / malformed → rejected.
	raw, _ := proto.Marshal(&corev1.PostureUpdate{Subject: "agent-A", Compliant: true})
	if err := sub.Apply(raw); err == nil {
		t.Error("an unsigned posture update was accepted")
	}
	if err := sub.Apply([]byte("\xff\xffnope")); err == nil {
		t.Error("a malformed posture update was accepted")
	}
}

// The TAMPER-LOCKOUT demonstrated with real TLS (D85/D92): a policy requiring an
// attested compliant device DENIES a device with no published posture, and ALLOWS one
// with compliant posture published — the same identity, gated by device trust.
func TestPostureTamperLockout(t *testing.T) {
	up, hit := accessUpstream(t)
	// Gate on has_posture ALONE — this is the tamper-lockout guard (D85): an attested
	// device (posture present) is trusted, an unattested one (posture absent) is not.
	// Compliance gating is a separate concern (D89); isolating has_posture here means
	// the test fails if the enrichment ever claims posture-present for an absent device.
	pol, err := policy.New(context.Background(), "posture", "1", `package openshield
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

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)
	financeCert := ca.clientCert(t, "alice@corp", "finance")
	client := accessClient(financeCert, ca.pool)

	// No posture published → unattested device → DENIED (the tamper-lockout).
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no-posture device = %d, want 403 (tamper-lockout — unattested device denied)", resp.StatusCode)
	}
	if hit.Load() {
		t.Error("an unattested device reached the service")
	}

	// Publish COMPLIANT posture through the REAL producer→subscriber→store path (not a direct
	// store.Set at the proxy's key — the false premise IDENT-1 exposed). The finance cert's CN is
	// "alice@corp", so real posture published for that agent identity lands under the same canonical
	// pseudonym the proxy derives from the cert.
	publishRealPosture(t, ps, "alice@corp", posture.Report{Compliant: true, DiskEncrypted: true, AgentPresent: true})
	resp2, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || !hit.Load() {
		t.Errorf("compliant device = %d (hit %v), want 200 + reached", resp2.StatusCode, hit.Load())
	}
}
