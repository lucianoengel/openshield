package controlplane_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SCIM (ZT-7): the LEAVER half of joiner/mover/leaver.
//
// The claim being tested is narrow on purpose: an identity provider deactivating a user removes their
// OpenShield access immediately, without an administrator remembering to do anything. Provisioning
// deliberately grants nothing — the provider says who exists, this product says what they may do — so a
// test that asserted "SCIM created a working operator" would be asserting the defect ZT-7 removed.

func scimReq(t *testing.T, s *controlplane.Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.ScimHandler().ServeHTTP(rec, r)
	return rec
}

func TestScimDeactivationRemovesAccessImmediately(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "grace@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	// An operator with real access, granted the normal way.
	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	state := certFor(t, who, "admin")
	gate := controlplane.RequireTierForTest(s, "analyst")
	if code := serve(t, gate, state); code != http.StatusOK {
		t.Fatalf("the operator did not have access to begin with: %d", code)
	}

	// THE PROVIDER DEACTIVATES THEM. This is the whole feature.
	rec := scimReq(t, s, http.MethodPatch, "/scim/v2/Users/"+who, "scim-secret",
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("SCIM deactivation returned %d: %s", rec.Code, rec.Body.String())
	}

	// ACCESS IS GONE, on the certificate they already hold.
	if code := serve(t, gate, state); code != http.StatusForbidden {
		t.Fatalf("a SCIM-deactivated operator still had access (%d) holding the same certificate. "+
			"Deprovisioning that waits for a credential to expire is not deprovisioning", code)
	}
	if controlplane.ScimDeprovisioned() == 0 {
		t.Error("the deprovisioning was not counted")
	}
}

// TestScimAcceptsTheOtherPatchShapeAndDelete — providers differ, and a deprovisioning that works against
// one identity provider and silently no-ops against another is the worst kind of half-working.
func TestScimAcceptsTheOtherPatchShapeAndDelete(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")

	for _, c := range []struct {
		name, who, method, body string
	}{
		{"value-object patch", "heidi@corp.example", http.MethodPatch,
			`{"Operations":[{"op":"replace","value":{"active":false}}]}`},
		{"PUT replace", "ivan@corp.example", http.MethodPut, `{"userName":"ivan@corp.example","active":false}`},
		{"DELETE", "judy@corp.example", http.MethodDelete, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			who := c.who
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })
			if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
				t.Fatal(err)
			}
			rec := scimReq(t, s, c.method, "/scim/v2/Users/"+who, "scim-secret", c.body)
			if rec.Code >= 300 {
				t.Fatalf("%s returned %d: %s", c.name, rec.Code, rec.Body.String())
			}
			state := certFor(t, who, "admin")
			if code := serve(t, controlplane.RequireTierForTest(s, "analyst"), state); code != http.StatusForbidden {
				t.Fatalf("%s did not remove access: %d", c.name, code)
			}
		})
	}
}

// TestScimProvisioningGrantsNothing is the decision that keeps authorization out of the credential path.
func TestScimProvisioningGrantsNothing(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "karl@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	rec := scimReq(t, s, http.MethodPost, "/scim/v2/Users", "scim-secret", `{"userName":"`+who+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("SCIM create returned %d: %s", rec.Code, rec.Body.String())
	}
	// A certificate claiming admin, and a SCIM record — and STILL no access, because a record is not a
	// grant. If this returned 200, the identity provider would be deciding authorization.
	state := certFor(t, who, "admin")
	if code := serve(t, controlplane.RequireTierForTest(s, "analyst"), state); code != http.StatusForbidden {
		t.Fatalf("a SCIM-provisioned user had access with no role granted (%d). Provisioning identifies; it "+
			"must not authorize, or the provider decides what an operator may do", code)
	}
}

// TestScimIsNotReachableWithoutItsOwnToken. A provisioning API can remove an administrator's access, so an
// operator credential reaching it would let an analyst deactivate an admin.
func TestScimIsNotReachableWithoutItsOwnToken(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)

	// Not configured at all: the endpoint does not exist.
	if rec := scimReq(t, s, http.MethodPost, "/scim/v2/Users", "", `{"userName":"x"}`); rec.Code != http.StatusNotFound {
		t.Errorf("an unconfigured SCIM endpoint answered %d, want 404 — a provisioning API that exists "+
			"without a credential is an unauthenticated way into the roster", rec.Code)
	}

	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	for _, tok := range []string{"", "wrong", "scim-secre"} {
		if rec := scimReq(t, s, http.MethodPost, "/scim/v2/Users", tok, `{"userName":"x"}`); rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q reached SCIM with %d, want 401", tok, rec.Code)
		}
	}
}

// TestAnOperatorCredentialCannotReachScim closes the escalation directly: the SCIM route ignores the
// operator tiers, so presenting an analyst certificate is not a way in.
func TestAnOperatorCredentialCannotReachScim(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")

	r := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/someone@corp.example", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: certFor(t, "analyst-mallory", "analyst").PeerCertificates}
	rec := httptest.NewRecorder()
	s.ScimHandler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an operator certificate reached the SCIM endpoint (%d). An analyst able to deprovision an "+
			"admin is a privilege escalation through a provisioning API", rec.Code)
	}
}
