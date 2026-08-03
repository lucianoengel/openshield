package controlplane_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
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

// scimServer is a control plane with SCIM enabled AND operator SSO configured.
//
// The SSO half is not incidental setup: SCIM is the identity provider's provisioning channel, so a
// SCIM-provisioned operator's principal is `oidc:<issuer>#<userName>` (CONSOLE-1). Without a configured
// verifier there is no issuer, and provisioning is refused rather than recorded under a guessed
// namespace — see TestScimWithoutSsoConfiguredIsRefused.
func scimServer(t *testing.T, pool *pgxpool.Pool) *controlplane.Server {
	t.Helper()
	s := controlplane.New(pool)
	s.SetOperatorOIDC(stubVerifier{token: "unused", subject: "unused"})
	return s
}

// scimP is the principal a SCIM-provisioned userName logs in as.
func scimP(userName string) string { return "oidc:https://idp.test#" + userName }

// serveToken presents an operator BEARER token, which is the credential SCIM actually governs.
//
// These cases used to present a CERTIFICATE for a SCIM-provisioned user, which conflated two separate
// credentials into one identity — precisely the conflation CONSOLE-1 removes. A certificate and an SSO
// login are different principals, and SCIM deactivating the identity provider's user does not, and
// cannot, revoke a certificate the same person also holds. That is a real residual, recorded in the
// spec; it is not something a test should hide by pretending the two are one.
func serveToken(t *testing.T, h http.Handler, token string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestScimDeactivationRemovesAccessImmediately(t *testing.T) {
	pool := requireDB(t)
	s := scimServer(t, pool)
	ctx := context.Background()
	const who = "grace@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, scimP(who)) })

	// An operator with real access, granted the normal way.
	if err := s.SetOperatorRole(ctx, scimP(who), "admin", "test"); err != nil {
		t.Fatal(err)
	}
	s.SetOperatorOIDC(stubVerifier{token: "grace-token", subject: who})
	gate := controlplane.RequireTierForTest(s, "analyst")
	if code := serveToken(t, gate, "grace-token"); code != http.StatusOK {
		t.Fatalf("the operator did not have access to begin with: %d", code)
	}

	// THE PROVIDER DEACTIVATES THEM. This is the whole feature.
	rec := scimReq(t, s, http.MethodPatch, "/scim/v2/Users/"+who, "scim-secret",
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("SCIM deactivation returned %d: %s", rec.Code, rec.Body.String())
	}

	// ACCESS IS GONE, on the token they already hold.
	if code := serveToken(t, gate, "grace-token"); code != http.StatusForbidden {
		t.Fatalf("a SCIM-deactivated operator still had access (%d) holding the same token. "+
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
	s := scimServer(t, pool)
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
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, scimP(who)) })
			if err := s.SetOperatorRole(ctx, scimP(who), "admin", "test"); err != nil {
				t.Fatal(err)
			}
			rec := scimReq(t, s, c.method, "/scim/v2/Users/"+who, "scim-secret", c.body)
			if rec.Code >= 300 {
				t.Fatalf("%s returned %d: %s", c.name, rec.Code, rec.Body.String())
			}
			s.SetOperatorOIDC(stubVerifier{token: "tok-" + who, subject: who})
			if code := serveToken(t, controlplane.RequireTierForTest(s, "analyst"), "tok-"+who); code != http.StatusForbidden {
				t.Fatalf("%s did not remove access: %d", c.name, code)
			}
		})
	}
}

// TestScimProvisioningGrantsNothing is the decision that keeps authorization out of the credential path.
func TestScimProvisioningGrantsNothing(t *testing.T) {
	pool := requireDB(t)
	s := scimServer(t, pool)
	ctx := context.Background()
	const who = "karl@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, scimP(who)) })

	rec := scimReq(t, s, http.MethodPost, "/scim/v2/Users", "scim-secret", `{"userName":"`+who+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("SCIM create returned %d: %s", rec.Code, rec.Body.String())
	}
	// A valid token and a SCIM record — and STILL no access, because a record is not a grant. If this
	// returned 200, the identity provider would be deciding authorization.
	//
	// A token rather than a certificate: an SSO principal has no embedded role to fall back to, so this
	// asserts the SCIM record grants nothing rather than accidentally asserting that a certificate the
	// same person holds is a separate principal (true, and a different test's job).
	s.SetOperatorOIDC(stubVerifier{token: "karl-token", subject: who})
	if code := serveToken(t, controlplane.RequireTierForTest(s, "analyst"), "karl-token"); code != http.StatusForbidden {
		t.Fatalf("a SCIM-provisioned user had access with no role granted (%d). Provisioning identifies; it "+
			"must not authorize, or the provider decides what an operator may do", code)
	}
}

// TestScimIsNotReachableWithoutItsOwnToken. A provisioning API can remove an administrator's access, so an
// operator credential reaching it would let an analyst deactivate an admin.
func TestScimIsNotReachableWithoutItsOwnToken(t *testing.T) {
	pool := requireDB(t)
	s := scimServer(t, pool)

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
	s := scimServer(t, pool)
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
