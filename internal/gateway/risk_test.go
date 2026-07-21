package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/policy"
)

func TestRiskStoreSetGet(t *testing.T) {
	rs := gateway.NewRiskStore()
	if _, ok := rs.Get("nobody"); ok {
		t.Error("an unpublished subject reported a risk — absent must be has=false")
	}
	rs.Set("sub_x", 0.9)
	if s, ok := rs.Get("sub_x"); !ok || s != 0.9 {
		t.Errorf("Get after Set = %v/%v, want 0.9/true", s, ok)
	}
}

// subjectOf resolves the pseudonymous subject the gateway will compute for a client
// certificate, so the test can publish risk for exactly that subject.
func subjectOf(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.FromClientCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	return id.Subject
}

// Continuous verification (D89): an authorized identity is allowed while its risk is
// absent, and DENIED once a high risk is published — the access is cut mid-session by
// the LOCAL policy reading published risk (T2). Real TLS, real client certs.
func TestRiskContinuousVerification(t *testing.T) {
	up, hit := accessUpstream(t)

	// finance is authorized, but any subject with risk >= 0.8 is blocked.
	pol, err := policy.New(context.Background(), "riskcv", "1", `package openshield
import rego.v1
authorized if { input.context.role == "finance" }
high_risk if { input.context.has_risk_score; input.context.risk_score >= 0.8 }
decision := {"action":"BLOCK","reason":"risk too high","confidence":0.9} if { high_risk }
decision := {"action":"ALLOW","reason":"authorized","confidence":0.9} if { authorized; not high_risk }
decision := {"action":"BLOCK","reason":"not authorized","confidence":0.9} if { not authorized }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	rs := gateway.NewRiskStore()
	ap.SetRiskStore(rs)

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)
	financeCert := ca.clientCert(t, "alice@corp", "finance")
	client := accessClient(financeCert, ca.pool)

	// No risk published → authorized → reaches the service.
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !hit.Load() {
		t.Fatalf("with no risk, finance = %d (hit %v), want 200 + reached", resp.StatusCode, hit.Load())
	}

	// Publish HIGH risk for this subject → access cut mid-session.
	hit.Store(false)
	rs.Set(subjectOf(t, financeCert), 0.95)
	resp2, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("after high risk published, finance = %d, want 403 (continuous verification)", resp2.StatusCode)
	}
	if hit.Load() {
		t.Error("the service was reached despite high published risk — continuous verification failed")
	}
}
