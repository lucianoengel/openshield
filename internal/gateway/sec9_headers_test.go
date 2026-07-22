package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/policy"
)

// SEC-9: a client-supplied identity header (X-Authenticated-User) and a pre-set
// X-OpenShield-Subject must NOT reach the backend; the backend receives ONLY the
// gateway-authoritative verified subject, matching the client cert's pseudonym.
func TestAccessProxyStripsSpoofedIdentityHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)

	pol, err := policy.New(t.Context(), "access", "1", `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"ok","confidence":0.9}`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)
	cert := ca.clientCert(t, "alice@corp", "finance")
	client := accessClient(cert, ca.pool)

	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	// The client tries to spoof its identity AND pre-set the trusted header.
	req.Header.Set("X-Authenticated-User", "admin")
	req.Header.Set("X-Openshield-Subject", "sub_someone_else")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if v := got.Get("X-Authenticated-User"); v != "" {
		t.Errorf("backend received spoofed X-Authenticated-User=%q — it must be stripped", v)
	}
	// The reverse proxy legitimately sets X-Forwarded-For to the REAL connecting IP; the
	// point is the client's SPOOFED value must not survive in the chain.
	if v := got.Get("X-Forwarded-For"); strings.Contains(v, "10.0.0.1") {
		t.Errorf("backend X-Forwarded-For=%q still contains the client's spoofed 10.0.0.1", v)
	}
	// The injected subject is the VERIFIED cert pseudonym, not the client's spoof.
	want := subjectOf(t, cert)
	if v := got.Get("X-Openshield-Subject"); v != want {
		t.Errorf("backend X-Openshield-Subject=%q, want the verified pseudonym %q (not the client's spoof)", v, want)
	}
	if got.Get("X-Openshield-Subject") == "sub_someone_else" {
		t.Error("the client's pre-set X-Openshield-Subject reached the backend — spoof succeeded")
	}
}
