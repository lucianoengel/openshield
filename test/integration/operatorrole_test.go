//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// ZT-7 AGAINST THE REAL SERVER, over real mutual TLS, with the role changed by the real CLI.
//
// The package tests for this drive an httptest handler with a synthesised TLS state. They prove the gate's
// logic and they cannot prove the WIRING: that the shipped binary reads the same table, that
// `openshield-server operator-role set` writes what the running server reads, and that the change is
// visible to a connection already established. Every defect this session has found lived in exactly that
// gap.
//
// THE SAME CLIENT AND THE SAME CERTIFICATE ARE USED THROUGHOUT EACH CASE. That is the property under test:
// before ZT-7 the only way to change an operator's authority was to issue a new certificate, so an
// assertion that reissues one is testing certificate issuance rather than the thing that was broken.

// operatorRoleCmd runs the operator-role subcommand against the stack's database, the way an operator
// would — not through a network route, because handing out admin deliberately is not one (D51).
func operatorRoleCmd(t *testing.T, stack *Stack, args ...string) string {
	t.Helper()
	out, err := runCapture(t, "openshield-server", []string{"OPENSHIELD_DSN=" + stack.DSN},
		append([]string{"operator-role"}, args...)...)
	if err != nil {
		t.Fatalf("operator-role %v: %v\n%s", args, err, out)
	}
	return out
}

// get performs a request and returns the status, draining the body so the connection is reusable — the
// reuse matters here, since part of the point is that a role change applies to an EXISTING session.
func opGet(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestAnOperatorsRoleChangesWithoutANewCertificate is the ZT-7 acceptance case.
func TestAnOperatorsRoleChangesWithoutANewCertificate(t *testing.T) {
	p := newPKI(t)
	stack, _, base := mtlsServer(t, p)

	// A certificate that says RESPONDER, and it never changes.
	const who = "carol"
	client := p.operator(t, "responder", who)

	// `/alerts/ack` requires responder; `/alerts` requires analyst.
	const respRoute, analystRoute = "/alerts/ack", "/alerts"

	// FIRST, WITH NO RECORD: the legacy fallback authorizes from the certificate, so an existing
	// deployment is not locked out by the migration.
	if code := opGet(t, client, base+respRoute); code == http.StatusUnauthorized {
		t.Fatalf("the operator certificate was not accepted at all (%d) — this case is about authorization, "+
			"so authentication has to work first", code)
	}

	// RECORD THE ROLE, then demote. Both through the shipped CLI, against the running server.
	operatorRoleCmd(t, stack, "set", who, "responder")
	if code := opGet(t, client, base+respRoute); code == http.StatusForbidden {
		t.Fatalf("a recorded responder was refused a responder route (403) — the server is not reading what " +
			"the CLI wrote")
	}

	operatorRoleCmd(t, stack, "set", who, "analyst")
	// The demotion must be visible to the SAME client on the SAME certificate, with no restart of either
	// side. Retried briefly only because the CLI and the server are separate processes; the server holds no
	// cache, so this settles immediately in practice.
	if code := eventuallyStatus(t, client, base+respRoute, http.StatusForbidden); code != http.StatusForbidden {
		t.Fatalf("after `operator-role set %s analyst`, the responder route still returned %d. The SAME "+
			"certificate was presented throughout — an authorization change that needs a new certificate is "+
			"the defect ZT-7 exists to remove", who, code)
	}
	// And the tier they still hold works, so the demotion removed exactly what it should and no more.
	if code := opGet(t, client, base+analystRoute); code == http.StatusForbidden {
		t.Fatalf("the demoted analyst lost analyst access too (403)")
	}

	// REVOCATION, also through the CLI, also on the same certificate.
	operatorRoleCmd(t, stack, "revoke", who)
	if code := eventuallyStatus(t, client, base+analystRoute, http.StatusForbidden); code != http.StatusForbidden {
		t.Fatalf("a revoked operator still reached an analyst route (%d) holding a valid certificate. "+
			"Revocation that waits for a certificate to expire is not revocation", code)
	}

	// The listing shows the revocation as a FACT rather than an absence, which is what makes an access
	// review possible.
	if out := operatorRoleCmd(t, stack, "list"); !contains(out, who) || !contains(out, "REVOKED") {
		t.Errorf("`operator-role list` does not show %s as revoked:\n%s", who, out)
	}
}

// eventuallyStatus polls until the status matches or the deadline passes, returning the last one seen.
func eventuallyStatus(t *testing.T, c *http.Client, url string, want int) int {
	t.Helper()
	last := 0
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		last = opGet(t, c, url)
		if last == want {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
	return last
}

// TestAnSsoOperatorIsAuthorizedByTheServerAgainstTheRealBinary is the second half of ZT-7 end to end.
//
// The token authenticates; the record authorizes. A valid token with no record must reach nothing, because
// an SSO operator has no certificate and therefore no embedded role to fall back to.
func TestAnSsoOperatorIsAuthorizedByTheServerAgainstTheRealBinary(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	work := t.TempDir()
	keyDir := filepath.Join(work, "operator-oidc")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The key has to be on disk before the server boots: a misconfigured issuer aborts startup, which is
	// the intended behaviour and means this cannot be written afterwards.
	writeOIDCKey(t, keyDir, "op1", priv)

	const issuer = "https://idp.operators.test"
	addr := "127.0.0.1:" + freePort(t)
	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
		"OPENSHIELD_OPERATOR_OIDC_ISSUER=" + issuer,
		"OPENSHIELD_OPERATOR_OIDC_AUDIENCE=openshield-operators",
		"OPENSHIELD_OPERATOR_OIDC_KEYS_DIR=" + keyDir,
	}, tlsEnv(m)...))
	srv.WaitForOutput("operator SSO ACTIVE", 90*time.Second)
	waitTCP(t, addr, 60*time.Second)
	base := "https://" + addr

	const who = "dana@corp.example"
	token := signJWT(t, priv, "op1", map[string]any{
		"iss": issuer, "aud": "openshield-operators", "sub": who,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	// A client that trusts the server's CA but presents NO certificate — the SSO shape.
	client := p.bearerClient(t)
	req := func(tok string) int {
		r, err := http.NewRequest(http.MethodGet, base+"/alerts", nil)
		if err != nil {
			t.Fatal(err)
		}
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("GET /alerts: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// A VALID TOKEN AND NO RECORD IS NOT ACCESS. If this returned 200, the identity provider would be
	// deciding authorization and a demotion would not apply until the token expired.
	if code := req(token); code != http.StatusForbidden {
		t.Fatalf("a verified token with no operator record got %d, want 403", code)
	}
	// No token at all is unauthenticated, not merely unauthorized.
	if code := req(""); code != http.StatusUnauthorized {
		t.Errorf("a request with no credential got %d, want 401", code)
	}

	operatorRoleCmd(t, stack, "set", who, "analyst")
	if code := req(token); code != http.StatusOK {
		t.Fatalf("a granted SSO operator was refused: %d", code)
	}

	// AND THE RELAXATION IS NARROW. Enabling SSO makes a client certificate OPTIONAL at the handshake, not
	// unverified — a certificate from a CA this server does not trust must still be refused there, or the
	// change would have traded a working mutual-TLS gate for an open one.
	//
	// This is the assertion that makes the relaxation safe, so it is worth more than the positive case: a
	// test that only checked "SSO works" would pass just as happily against a listener that accepted any
	// certificate at all.
	// The client TRUSTS this server's CA and presents a certificate from a DIFFERENT one, so the only thing
	// that can fail is the server refusing the client — see foreignCertClient for why the obvious version of
	// this passes for the wrong reason.
	forged := p.foreignCertClient(t, newPKI(t), "admin", "mallory")
	if _, err := forged.Get(base + "/alerts"); err == nil {
		t.Fatal("a certificate issued by an UNTRUSTED CA was accepted once SSO made client certificates " +
			"optional. Optional must mean 'verified when presented', never 'not checked' — otherwise anyone " +
			"can mint an OU=admin leaf and the legacy fallback hands them the console")
	}

	// AND REVOCATION APPLIES TO THE TOKEN THEY ALREADY HOLD.
	operatorRoleCmd(t, stack, "revoke", who)
	deadline := time.Now().Add(30 * time.Second)
	code := 0
	for time.Now().Before(deadline) {
		if code = req(token); code == http.StatusForbidden {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if code != http.StatusForbidden {
		t.Fatalf("a revoked SSO operator still had access with the token they already held (%d). Revocation "+
			"that waits for a token to expire is not revocation", code)
	}
}
