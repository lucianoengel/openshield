package gateway_test

import (
	"context"
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

func TestApplyPostureUpdate(t *testing.T) {
	store := gateway.NewPostureStore()
	data, _ := proto.Marshal(&corev1.PostureUpdate{Subject: "sub_x", Compliant: true, DiskEncrypted: true})
	if err := gateway.ApplyPostureUpdate(data, store); err != nil {
		t.Fatal(err)
	}
	dp, ok := store.Get("sub_x")
	if !ok || !dp.HasPosture || !dp.Compliant {
		t.Errorf("store after apply = %+v/%v, want present + compliant", dp, ok)
	}
	if err := gateway.ApplyPostureUpdate([]byte("\xff\xffnope"), store); err == nil {
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
