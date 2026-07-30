package controlplane_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
