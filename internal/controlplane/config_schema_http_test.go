package controlplane_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lucianoengel/openshield/internal/config"
	"github.com/lucianoengel/openshield/internal/controlplane"
)

// D467: GET /config/schema is what a schema-driven configuration UI renders from, and it had NO TEST.
//
// PLAT-5's argument is that there is one declaration, used for both reading and describing, so a form
// cannot offer a setting the binary ignores. SEC-A then added an operational range and a direction to
// that declaration and neither reached this endpoint — so the console would have rendered the settings
// that decide whether anything is detected at all looking exactly like the rest: no range, no help, no
// indication which way is dangerous.
//
// Asserted at the HTTP boundary rather than on Describe() alone, because "the schema carries it" and
// "the console can see it" are different claims, and the gap between them is where D418's whole class of
// defect lives.
func TestTheConfigSchemaEndpointCarriesBoundsAndDirection(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	srv.SetConfigResolver(config.New(config.ServerFields, config.EnvSource{}))

	req := httptest.NewRequest(http.MethodGet, "/config/schema", nil)
	// The endpoint requires a verified operator identity; an admin certificate is what a console
	// presents.
	ca := newOneCA(t)
	leaf := ca.leaf(t, "console", "admin", nil)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}

	// THROUGH THE REAL GATE. requireTier is what puts the authenticated principal on the request
	// context (CONSOLE-1), and the handlers read it from there — so calling the inner mux directly
	// would test a request that production never makes, and would answer 401 for a reason production
	// never hits.
	rr := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAdmin, srv.OperatorReadHandler()).
		ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /config/schema = %d, body %q", rr.Code, rr.Body.String())
	}

	var fields []config.FieldDesc
	if err := json.Unmarshal(rr.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decoding the schema: %v", err)
	}
	byKey := map[string]config.FieldDesc{}
	for _, f := range fields {
		byKey[f.Key] = f
	}

	d, ok := byKey["OPENSHIELD_OVERDUE_THRESHOLD"]
	if !ok {
		t.Fatal("the dead-man's-switch threshold is not in the served schema")
	}
	if d.Range == "" || d.Why == "" {
		t.Errorf("served range=%q why=%q — a form cannot show the bound or what exceeding it costs, so "+
			"an operator meets both by having a value refused", d.Range, d.Why)
	}
	if d.Sensitivity == "" {
		t.Error("served sensitivity is empty — the setting that decides whether a killed agent is ever " +
			"reported renders identically to every cosmetic one")
	}
	if c := byKey["OPENSHIELD_CORRELATE_INTERVAL"]; !c.ZeroDisables {
		t.Error("the served schema does not say zero DISABLES scheduled correlation — the single most " +
			"dangerous value looks like an ordinary end of the range")
	}

	// AND NO SECRET LEAKS THROUGH THE NEW FIELDS. A schema is an output path like any other, and the
	// three fields added here are the newest place a value could escape.
	for _, f := range fields {
		if !f.Secret {
			continue
		}
		if f.Default != "" || f.Range != "" || f.Why != "" {
			t.Errorf("secret %s describes default=%q range=%q why=%q", f.Key, f.Default, f.Range, f.Why)
		}
	}
}
