//go:build integration

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// CONSOLE-1 AGAINST THE SHIPPED BINARIES: an automation calls the operator API as ITSELF.
//
// The package tests prove the credential's logic against a handler. What they cannot prove is the part
// that was actually broken twice in this project — the WIRING. Operator SSO shipped unusable because the
// listener demanded a client certificate at the handshake, before the bearer token was read (D375), and
// a machine credential is the same shape: it has no certificate either. Gating the relaxation on SSO
// alone would have shipped this feature unreachable on every deployment without an identity provider,
// and no package test could see it.
//
// So this drives the real `openshield-server machine-credential` command against the real listener over
// real TLS, with NO client certificate and NO identity provider configured.

// machineCredentialCmd runs the subcommand against the stack's database, returning stdout — which is
// where the token is printed, deliberately separated from the prose on stderr.
func machineCredentialCmd(t *testing.T, stack *Stack, args ...string) string {
	t.Helper()
	out, err := runCapture(t, "openshield-server", []string{"OPENSHIELD_DSN=" + stack.DSN},
		append([]string{"machine-credential"}, args...)...)
	if err != nil {
		t.Fatalf("machine-credential %v: %v\n%s", args, err, out)
	}
	return out
}

// machineToken pulls the `osm_` line out of the command's combined output.
func machineToken(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "osm_") {
			return line
		}
	}
	t.Fatalf("no machine token in:\n%s", out)
	return ""
}

func TestAnAutomationCallsTheOperatorAPIAsItself(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	addr := "127.0.0.1:" + freePort(t)
	// NO identity provider is configured, and that is the case that would have been broken: the
	// handshake relaxation used to depend on operator SSO alone.
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
		"OPENSHIELD_OPERATOR_MACHINE_TOKENS=1",
	}, tlsEnv(m)...))
	waitTCP(t, addr, 60*time.Second)
	base := "https://" + addr

	tok := machineToken(t, machineCredentialCmd(t, stack, "issue", "ci-runner", "--ttl", "24h"))

	// A client that trusts the server's CA and presents NO certificate — the automation's shape.
	client := p.bearerClient(t)
	get := func(path, bearer string) int {
		t.Helper()
		r, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	// ISSUING GRANTS NOTHING — 403 and not 401, so it AUTHENTICATED. The distinction tells an operator
	// to grant a role rather than to re-issue the token.
	if code := get("/alerts", tok); code != http.StatusForbidden {
		t.Fatalf("a freshly issued machine credential with no grant got %d, want 403. 401 would mean the "+
			"credential never authenticated — the D375 shape, where the listener refuses a "+
			"certificate-less handshake before any token is read", code)
	}
	operatorRoleCmd(t, stack, "set", "svc:ci-runner", "analyst")
	if code := get("/alerts", tok); code != http.StatusOK {
		t.Fatalf("a granted machine credential was refused: %d", code)
	}

	// ROTATION invalidates the previous secret immediately, through the real command.
	rotated := machineToken(t, machineCredentialCmd(t, stack, "rotate", "ci-runner", "--ttl", "24h"))
	if rotated == tok {
		t.Fatal("rotate returned the same secret")
	}
	if code := get("/alerts", rotated); code != http.StatusOK {
		t.Errorf("the rotated secret does not work: %d", code)
	}
	if code := get("/alerts", tok); code != http.StatusUnauthorized {
		t.Errorf("the PREVIOUS secret still authenticates after rotation (%d) — two live secrets for one "+
			"identity is the state rotation exists to end", code)
	}

	// REVOCATION takes effect on the next request, with no restart.
	machineCredentialCmd(t, stack, "revoke", "ci-runner")
	if code := get("/alerts", rotated); code != http.StatusUnauthorized {
		t.Errorf("a REVOKED machine credential got %d, want 401", code)
	}

	// The listing shows the identity and its state, which is what an access review reads.
	if out := machineCredentialCmd(t, stack, "list"); !strings.Contains(out, "svc:ci-runner") ||
		!strings.Contains(out, "REVOKED") {
		t.Errorf("`machine-credential list` does not show the revoked identity:\n%s", out)
	}
}
