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

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
)

// SEC-1: a signed posture update is applied; an unsigned/forged one is rejected — so a
// publisher cannot forge Compliant=true and defeat the D85 tamper-lockout.
func TestPostureSubscriberVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	store := gateway.NewPostureStore()
	sub := gateway.NewPostureSubscriber(store, pub)

	signPosture := func(signer ed25519.PrivateKey, subject string, compliant bool) []byte {
		payload, _ := proto.Marshal(&corev1.PostureUpdate{Subject: subject, Compliant: compliant, DiskEncrypted: true})
		data, _ := gateway.SignUpdate(payload, signer)
		return data
	}

	// Valid signed → applied.
	if err := sub.Apply(signPosture(priv, "sub_x", true)); err != nil {
		t.Fatalf("a validly-signed posture update was rejected: %v", err)
	}
	dp, ok := store.Get("sub_x")
	if !ok || !dp.HasPosture || !dp.Compliant {
		t.Errorf("store = %+v/%v, want present + compliant", dp, ok)
	}

	// An attacker forging Compliant=true for a NEW subject with the wrong key is rejected —
	// the tamper-lockout holds (that subject keeps absent posture and is denied).
	if err := sub.Apply(signPosture(otherPriv, "sub_attacker", true)); err == nil {
		t.Error("a wrong-key posture forgery was accepted — the tamper-lockout is defeated")
	}
	if _, ok := store.Get("sub_attacker"); ok {
		t.Error("a forged posture reached the store")
	}
	// A raw (unsigned) PostureUpdate — not wrapped in a SignedUpdate — is rejected.
	raw, _ := proto.Marshal(&corev1.PostureUpdate{Subject: "sub_x", Compliant: true})
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

	// Publish COMPLIANT posture for this subject → attested → ALLOWED.
	ps.Set(subjectOf(t, financeCert), core.DevicePosture{Compliant: true, DiskEncrypted: true, AgentPresent: true})
	resp2, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || !hit.Load() {
		t.Errorf("compliant device = %d (hit %v), want 200 + reached", resp2.StatusCode, hit.Load())
	}
}
