package controlplane_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// ZT-7: THE ROLE MUST BE CHANGEABLE WITHOUT REISSUING A CERTIFICATE.
//
// The defect these cover: the role was stamped into the client certificate's Subject OU and read from there
// on every request, so authorization was frozen for the certificate's lifetime. Demoting a responder, or
// removing someone's access entirely, did not take effect until that certificate expired — and there was no
// "revoke this operator's responder rights now" primitive at all.
//
// EVERY CASE HERE PRESENTS THE SAME CERTIFICATE THROUGHOUT. That is the point: if the assertions could be
// satisfied by issuing a different certificate, they would be testing certificate issuance rather than the
// thing that was broken.

// certFor builds a verified-peer TLS state for an identity with a role in its OU, the way the CA issues one.
func certFor(t *testing.T, identity, ouRole string) *tls.ConnectionState {
	t.Helper()
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Subject: pkix.Name{CommonName: identity, OrganizationalUnit: []string{ouRole}},
	}}}
}

func serve(t *testing.T, h http.Handler, state *tls.ConnectionState) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	req.TLS = state
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestARoleChangeTakesEffectWithoutReissuingTheCertificate(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "operator-zt7-demote"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	// The certificate says RESPONDER and never changes for the whole test.
	state := certFor(t, who, "responder")
	gate := controlplane.RequireTierForTest(s, "responder")

	if err := s.SetOperatorRole(ctx, who, "responder", "test"); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, gate, state); code != http.StatusOK {
		t.Fatalf("a responder was refused a responder route: %d", code)
	}

	// THE DEMOTION. Before ZT-7 this was impossible without reissuing the certificate.
	if err := s.SetOperatorRole(ctx, who, "analyst", "test"); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, gate, state); code != http.StatusForbidden {
		t.Fatalf("after demotion to analyst the responder route returned %d, want 403. The SAME certificate "+
			"was presented throughout — if this passes only when a new certificate is issued, the "+
			"authorization change is still on a certificate-lifetime delay", code)
	}

	// And the tier they DO hold still works, so the demotion removed exactly what it should.
	if code := serve(t, controlplane.RequireTierForTest(s, "analyst"), state); code != http.StatusOK {
		t.Fatalf("a demoted analyst lost their analyst access too: %d", code)
	}
}

func TestRevocationIsImmediateAndBeatsTheCertificate(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "operator-zt7-revoked"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	// A certificate that says ADMIN — the strongest thing the old scheme could assert.
	state := certFor(t, who, "admin")
	gate := controlplane.RequireTierForTest(s, "analyst")

	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, gate, state); code != http.StatusOK {
		t.Fatalf("an admin was refused: %d", code)
	}

	if err := s.RevokeOperator(ctx, who, "test"); err != nil {
		t.Fatal(err)
	}
	if code := serve(t, gate, state); code != http.StatusForbidden {
		t.Fatalf("a REVOKED operator holding an admin certificate got %d, want 403. Revocation that does not "+
			"beat the certificate is not revocation", code)
	}
}

// TestRevocationIsARowSoItCannotBeUndoneByDeletion is the reversal worth pinning.
//
// If revocation were implemented as a DELETE, removing the row would fall back to the certificate's
// embedded role — so "revoke" would silently RESTORE whatever the certificate said. That is the opposite of
// the intent, and it is the kind of inversion nobody notices until an incident.
func TestRevocationIsARowSoItCannotBeUndoneByDeletion(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "operator-zt7-rowcheck"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	if err := s.RevokeOperator(ctx, who, "test"); err != nil {
		t.Fatal(err)
	}
	var revoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked FROM operator_roles WHERE identity = $1`, who).Scan(&revoked); err != nil {
		t.Fatalf("revocation left no row, so it is an absence rather than a fact — and an absence falls back "+
			"to the certificate: %v", err)
	}
	if !revoked {
		t.Fatal("the row does not record the revocation")
	}
}

// TestAnOperatorWithNoRowFallsBackToItsCertificate pins the migration path.
//
// Every operator certificate already issued carries a role. Switching to database-only authorization in one
// step would lock every existing deployment out of its own control plane — including the admin who would
// have to fix it. So no row means the certificate still decides, and the server says so once.
func TestAnOperatorWithNoRowFallsBackToItsCertificate(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	state := certFor(t, "operator-zt7-legacy", "admin")
	if code := serve(t, controlplane.RequireTierForTest(s, "responder"), state); code != http.StatusOK {
		t.Fatalf("an operator with no row was refused (%d) — that is the correct END STATE but it is a "+
			"lockout as a migration step, which is why the fallback exists", code)
	}
}

// TestStrictModeRefusesACertificateEmbeddedRole is the end state the fallback is migrating towards.
func TestStrictModeRefusesACertificateEmbeddedRole(t *testing.T) {
	t.Setenv("OPENSHIELD_OPERATOR_ROLES_STRICT", "1")
	pool := requireDB(t)
	s := controlplane.New(pool)
	state := certFor(t, "operator-zt7-strict", "admin")
	if code := serve(t, controlplane.RequireTierForTest(s, "analyst"), state); code != http.StatusForbidden {
		t.Fatalf("strict mode honoured a role that exists only in the certificate: %d", code)
	}
}

// TestAnAgentCertificateCannotBeGrantedAnOperatorTier keeps the two credential families apart.
//
// An agent's certificate is a FLEET credential, issued to every endpoint. If one could be given an operator
// tier here, compromising any single endpoint would hand over the console.
func TestAnAgentCertificateCannotBeGrantedAnOperatorTier(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	if err := s.SetOperatorRole(ctx, "agent-42", "agent", "test"); err == nil {
		t.Fatal("`agent` was accepted as an operator role — a fleet credential must not be grantable console " +
			"access, or one compromised endpoint is a compromised console")
	}
	if err := s.SetOperatorRole(ctx, "someone", "superuser", "test"); err == nil {
		t.Fatal("an unknown role was accepted; the operator role set is closed")
	}
}

// ZT-7 SECOND HALF: OPERATOR SSO.
//
// The property that matters is not "a token works" — it is that a token authenticates and does NOT
// authorize. Mapping an IdP group claim to a tier is the conventional shape and it reintroduces the exact
// defect the first half removed, with a shorter fuse: a token issued before a demotion still asserts the
// old group until it expires.

// stubVerifier accepts one token and maps it to a subject, so these cases are about the authorization
// wiring rather than about JWT validation — which is tested against real signatures in the gateway package.
type stubVerifier struct {
	token   string
	subject string
	// proof, when set, makes this token sender-constrained: it verifies only when the matching proof is
	// presented.
	proof string
}

// bound simulates a sender-constrained token: it needs a matching proof.
func (s stubVerifier) VerifySubjectWithProof(tok, proof, _, _ string, requireBound bool) (string, error) {
	if tok != s.token {
		return "", errors.New("bad token")
	}
	if s.proof == "" {
		// An unbound token. Refused only when the deployment requires binding.
		if requireBound {
			return "", errors.New("token is not sender-constrained")
		}
		return s.subject, nil
	}
	if proof != s.proof {
		return "", errors.New("missing or wrong DPoP proof")
	}
	return s.subject, nil
}

func bearerReq(t *testing.T, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func serveReq(h http.Handler, req *http.Request) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestAnSsoOperatorIsAuthorizedByTheServerNotTheToken(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "alice@corp.example"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })
	s.SetOperatorOIDC(stubVerifier{token: "good", subject: who})

	gate := controlplane.RequireTierForTest(s, "responder")

	// A VALID TOKEN AND NO RECORD IS NOT ACCESS. An SSO operator has no certificate, so there is no
	// embedded role to fall back to — they are strict by construction.
	if code := serveReq(gate, bearerReq(t, "good")); code != http.StatusForbidden {
		t.Fatalf("a verified token with no operator record got %d, want 403. If a token alone grants access, "+
			"the IdP is deciding authorization and a demotion does not take effect until it expires", code)
	}

	if err := s.SetOperatorRole(ctx, who, "responder", "test"); err != nil {
		t.Fatal(err)
	}
	if code := serveReq(gate, bearerReq(t, "good")); code != http.StatusOK {
		t.Fatalf("a granted SSO operator was refused: %d", code)
	}

	// AND THE DEMOTION APPLIES TO THE TOKEN ALREADY ISSUED — the same property the certificate half has.
	if err := s.SetOperatorRole(ctx, who, "analyst", "test"); err != nil {
		t.Fatal(err)
	}
	if code := serveReq(gate, bearerReq(t, "good")); code != http.StatusForbidden {
		t.Fatalf("after demotion the SAME token still opened a responder route: %d", code)
	}
}

func TestRevokingAnSsoOperatorTakesEffectOnTheTokenTheyHold(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "bob@corp.example"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })
	s.SetOperatorOIDC(stubVerifier{token: "good", subject: who})
	gate := controlplane.RequireTierForTest(s, "analyst")

	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	if code := serveReq(gate, bearerReq(t, "good")); code != http.StatusOK {
		t.Fatalf("an SSO admin was refused: %d", code)
	}
	if err := s.RevokeOperator(ctx, who, "test"); err != nil {
		t.Fatal(err)
	}
	if code := serveReq(gate, bearerReq(t, "good")); code != http.StatusForbidden {
		t.Fatalf("a revoked SSO operator still had access with the token they already held: %d. Revocation "+
			"that waits for a token to expire is not revocation", code)
	}
}

func TestAnUnverifiableTokenIsNotAnIdentity(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	s.SetOperatorOIDC(stubVerifier{token: "good", subject: "carol@corp.example"})
	gate := controlplane.RequireTierForTest(s, "analyst")

	for _, tok := range []string{"", "wrong", "Bearer-ish"} {
		if code := serveReq(gate, bearerReq(t, tok)); code != http.StatusUnauthorized {
			t.Errorf("token %q got %d, want 401 — a token that does not verify is not a weaker identity, "+
				"it is no identity", tok, code)
		}
	}
}

func TestSsoIsOffUnlessConfigured(t *testing.T) {
	// A deployment that has not enabled SSO must not accept bearer tokens at all, or enabling an IdP would
	// be something that happens by accident.
	pool := requireDB(t)
	s := controlplane.New(pool)
	gate := controlplane.RequireTierForTest(s, "analyst")
	if code := serveReq(gate, bearerReq(t, "anything")); code != http.StatusUnauthorized {
		t.Fatalf("a bearer token was considered with no verifier configured: %d", code)
	}
}

// TestAStolenSenderConstrainedOperatorTokenIsUseless is the point of DPoP (ZT-7 residual).
//
// A plain bearer token is a password that happens to expire: whoever holds it is the operator. Binding it
// to a key means the token alone proves nothing, so capturing it — from a log, a proxy, a browser history —
// does not hand over the console.
func TestAStolenSenderConstrainedOperatorTokenIsUseless(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "erin@corp.example"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })
	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	s.SetOperatorOIDC(stubVerifier{token: "bound-token", subject: who, proof: "the-proof"})
	gate := controlplane.RequireTierForTest(s, "analyst")

	// WITH the proof: authorized.
	req := bearerReq(t, "bound-token")
	req.Header.Set("DPoP", "the-proof")
	if code := serveReq(gate, req); code != http.StatusOK {
		t.Fatalf("a bound token WITH its proof was refused: %d", code)
	}

	// THE TOKEN ALONE — exactly what an attacker who captured it would have.
	if code := serveReq(gate, bearerReq(t, "bound-token")); code != http.StatusUnauthorized {
		t.Fatalf("a sender-constrained token was accepted WITHOUT its proof (%d). That is a plain bearer "+
			"token with extra steps, and the whole reason to bind it is that capturing it should not be "+
			"enough", code)
	}

	// A proof under the wrong key is not better than none.
	wrong := bearerReq(t, "bound-token")
	wrong.Header.Set("DPoP", "some-other-proof")
	if code := serveReq(gate, wrong); code != http.StatusUnauthorized {
		t.Errorf("a token was accepted with a proof it was not bound to: %d", code)
	}
}

// TestRequiringDpopRefusesAnUnboundToken is the hardening switch.
//
// Without it, an identity provider that stops binding tokens — a misconfiguration, a downgrade, a
// migration — silently returns every operator to a stealable bearer credential, and nothing says so.
func TestRequiringDpopRefusesAnUnboundToken(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "frank@corp.example"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })
	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	s.SetOperatorOIDC(stubVerifier{token: "plain-token", subject: who}) // no proof: unbound
	gate := controlplane.RequireTierForTest(s, "analyst")

	// Default: an unbound token still works, because refusing before the issuer binds locks everyone out.
	if code := serveReq(gate, bearerReq(t, "plain-token")); code != http.StatusOK {
		t.Fatalf("an unbound token was refused with the requirement OFF: %d", code)
	}

	t.Setenv("OPENSHIELD_OPERATOR_OIDC_REQUIRE_DPOP", "1")
	if code := serveReq(gate, bearerReq(t, "plain-token")); code != http.StatusUnauthorized {
		t.Fatalf("an unbound token was accepted with the requirement ON: %d", code)
	}
}
