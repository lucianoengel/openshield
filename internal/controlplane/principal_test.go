package controlplane_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-1: one canonical operator principal, and four-eyes that compares the PERSON.
//
// Two defects, and the second is why fixing the first carelessly would have been worse than leaving it:
//
//   - `requireTier` authenticated a certificate OR a bearer token and then DISCARDED the identity. Eight
//     handlers re-derived it from the TLS peer certificate, which is empty for a bearer request, so an
//     SSO operator passed the tier gate and was refused by everything that needed to know who they were.
//   - Four-eyes is `requester <> approver`. A certificate minted `operator:<CN>` and a token minted the
//     raw `sub`, so threading the bearer identity through unchanged lets one human request from the CLI
//     and approve from the browser. The strings differ; the control is satisfied; two-person approval on
//     case closure, CONTAIN and fleet ENFORCEMENT_DISABLE collapses. Since SEC-D the row would have
//     recorded that as `strong` assurance.

// tokenReq builds a bearer-authenticated operator request — no client certificate at all.
func tokenReq(method, path, token string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// certReq builds a certificate-authenticated operator request.
func certReq(t *testing.T, ca *oneCA, method, path, cn, role string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	leaf := ca.leaf(t, cn, role, nil)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}
	return r
}

// TestABearerOnlyOperatorIsAttributed is the first defect, at the layer it lived on.
//
// The handler under test reads the operator identity to attribute an action. Before CONSOLE-1 it read
// `r.TLS`, so a perfectly well-authenticated SSO operator got 401 from a handler they had already been
// authorized to reach — the tier gate said yes and the handler said "client certificate required".
//
// Mutation: revert the context threading (have operatorIdentity read the TLS state again) → this FAILS
// with 401.
func TestABearerOnlyOperatorIsAttributed(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const sub = "sso-only@corp.example"
	principal := "oidc:https://idp.test#" + sub
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, principal) })

	s.SetOperatorOIDC(stubVerifier{token: "sso-token", subject: sub})
	if err := s.SetOperatorRole(ctx, principal, "admin", "test"); err != nil {
		t.Fatal(err)
	}

	// /cases/open attributes the case to the operator, so it exercises both halves: the tier gate must
	// admit the token, and the handler must then know who is calling.
	req := tokenReq(http.MethodPost, "/cases/open?subject=subject-x", "sso-token")
	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleResponder, s.OperatorReadHandler()).
		ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("a bearer-authenticated operator was refused by the HANDLER after passing the tier gate "+
			"(%d, %q). D373 shipped an authentication method that reached almost none of the product",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if rec.Code >= 300 {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}
}

// TestOneHumanWithTwoCredentialsCannotBeBothPairsOfEyes is the trap, and the reason CONSOLE-1 says it
// fixes both defects or neither.
//
// Mutation: compare `requester <> approver` (the principal strings) instead of the accounts → the
// approval succeeds and this FAILS.
func TestOneHumanWithTwoCredentialsCannotBeBothPairsOfEyes(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	const cert, token = "cert:mallory", "oidc:https://idp.test#mallory@corp.example"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM operator_identities WHERE account_id = 'person:mallory'`)
	})
	// One person, two credentials — the ordinary state of an operator who has a CLI certificate and an
	// SSO login.
	for _, p := range []string{cert, token} {
		if err := s.LinkOperatorIdentity(ctx, p, "person:mallory", "test"); err != nil {
			t.Fatal(err)
		}
	}

	id, err := s.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-console1",
		cert, "contain everything", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	err = s.ResolveApproval(ctx, id, token, true)
	if !errors.Is(err, controlplane.ErrFourEyes) {
		t.Fatalf("one human requested with a certificate and approved with a token, and got %v. Two "+
			"credentials are not two people: this is a four-eyes control that a single operator "+
			"satisfies alone, on case closure, CONTAIN and fleet ENFORCEMENT_DISABLE", err)
	}
	got, err := s.ApprovalFor(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-console1")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplane.ApprovalPending {
		t.Errorf("state = %q after the refusal, want still pending", got.State)
	}
}

// TestTwoRealOperatorsStillSatisfyFourEyes. A control that refuses everyone is an outage, and it is the
// failure this change could plausibly introduce — unlinked principals must keep working exactly as
// before, since an operator nobody has linked IS one person with one credential.
func TestTwoRealOperatorsStillSatisfyFourEyes(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	id, err := s.RequestApproval(ctx, controlplane.ApprovalSubjectResponseIntent, "intent-two-people",
		"cert:alice", "contain host A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResolveApproval(ctx, id, "cert:bob", true); err != nil {
		t.Fatalf("two distinct operators were refused: %v — the control must still permit the case it "+
			"exists to permit", err)
	}
}

// TestAnIdentityProviderSubjectCannotInheritACertificatesRole.
//
// Both were stored bare in one column before CONSOLE-1 — `certIdentity` returned the CommonName
// unprefixed and SCIM stored the raw `userName` — so a provider that called someone "alice" inherited
// whatever had been granted to the certificate whose CommonName is alice, and nothing recorded which
// one a row was for.
//
// Mutation: strip the namespace before the role lookup → the token holder inherits the certificate's
// admin role and this FAILS.
func TestAnIdentityProviderSubjectCannotInheritACertificatesRole(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const name = "collide@corp.example"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity LIKE '%' || $1`, name)
	})

	// A certificate holder is granted admin.
	if err := s.SetOperatorRole(ctx, "cert:"+name, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	// An identity provider mints a token whose subject is the same string.
	s.SetOperatorOIDC(stubVerifier{token: "collide-token", subject: name})

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTest(s, "admin").
		ServeHTTP(rec, tokenReq(http.MethodGet, "/alerts", "collide-token"))
	// 403, NOT MERELY "not 200". A 401 would mean the token never authenticated, and the test would then
	// pass for a reason having nothing to do with namespacing — the vacuous negative this suite keeps
	// finding. The token must be accepted as an identity and refused as an authorization.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("token holder got %d, want 403. A token subject equal to a certificate CommonName must "+
			"AUTHENTICATE and then be refused; if it inherited that certificate's admin role, an identity "+
			"provider decides who is an OpenShield administrator by choosing a username", rec.Code)
	}
}

// TestTheSameSubjectFromASecondIssuerIsADifferentOperator. `sub` is unique only within an issuer, so a
// principal that omits the issuer is a name two providers can both hand out.
func TestTheSameSubjectFromASecondIssuerIsADifferentOperator(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const sub = "shared-name@corp.example"
	granted := "oidc:https://idp.test#" + sub
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, granted) })

	if err := s.SetOperatorRole(ctx, granted, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	// A SECOND issuer, same subject.
	s.SetOperatorOIDC(stubVerifier{token: "other-token", subject: sub, issuer: "https://other-idp.test"})

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTest(s, "admin").
		ServeHTTP(rec, tokenReq(http.MethodGet, "/alerts", "other-token"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the second issuer's token got %d, want 403 — authenticated, and authorized for "+
			"nothing. Anyone who can stand up an identity provider this deployment trusts could "+
			"otherwise mint any operator they like", rec.Code)
	}
}

// TestABareIdentityCannotBeGranted. Every legacy row is in this shape, and the migration deliberately
// leaves them denying rather than guessing a namespace — so the grant path must refuse to create more.
func TestABareIdentityCannotBeGranted(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	err := s.SetOperatorRole(context.Background(), "alice", "admin", "test")
	if !errors.Is(err, controlplane.ErrBadPrincipal) {
		t.Fatalf("granting to a bare name returned %v — a bare identity does not record whether it is a "+
			"certificate CommonName or a provider subject, and either guess grants the wrong credential",
			err)
	}
	if !strings.Contains(err.Error(), "cert:") || !strings.Contains(err.Error(), "oidc:") {
		t.Errorf("the refusal does not show the accepted forms: %v", err)
	}
}
