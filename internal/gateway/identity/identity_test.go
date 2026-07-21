package identity_test

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/provision"
)

func leafFromPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCA(t *testing.T) (cert, key []byte) {
	t.Helper()
	c, k, err := provision.InitCA()
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

// A client cert resolves to a PSEUDONYMOUS subject (never the raw identity) and the
// group as the role (D86/D23).
func TestFromClientCertResolvesPseudonymousSubject(t *testing.T) {
	caCert, caKey := newCA(t)
	certPEM, _, err := provision.IssueClientCert(caCert, caKey, "alice@corp", "finance")
	if err != nil {
		t.Fatal(err)
	}

	id, err := identity.FromClientCert(leafFromPEM(t, certPEM))
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != "finance" {
		t.Errorf("role = %q, want finance (the authorization group)", id.Role)
	}
	if id.Subject == "" || !strings.HasPrefix(id.Subject, "sub_") {
		t.Errorf("subject = %q, want a pseudonym", id.Subject)
	}
	// The raw identity MUST NOT appear in the pseudonymous subject (D23).
	if strings.Contains(id.Subject, "alice") || strings.Contains(id.Subject, "corp") {
		t.Errorf("subject %q leaks the raw identity — it must be pseudonymised (D23)", id.Subject)
	}
}

// An agent or operator cert is NOT a client identity and is rejected (the D58 role
// discipline — a client cert is a distinct role).
func TestFromClientCertRejectsNonClient(t *testing.T) {
	caCert, caKey := newCA(t)
	for _, role := range []string{provision.RoleAgent, provision.RoleOperator} {
		certPEM, _, err := provision.IssueCert(caCert, caKey, "node1", role, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = identity.FromClientCert(leafFromPEM(t, certPEM))
		if err == nil {
			t.Errorf("a %s cert was accepted as a client identity — roles must stay distinct (D58)", role)
			continue
		}
		// It must be rejected specifically for NOT being a client cert (the role
		// check), not for some incidental reason — otherwise the role gate is dead.
		if !strings.Contains(err.Error(), "not a client certificate") {
			t.Errorf("a %s cert was rejected for the wrong reason (%v) — the client-role check must fire", role, err)
		}
	}
}

// The produced Context carries the identity + role but leaves device posture ABSENT,
// so a ZT policy still denies until the posture producer runs — the correct
// fail-closed default (D85). Authentication is not device trust.
func TestContextLeavesPostureAbsent(t *testing.T) {
	caCert, caKey := newCA(t)
	certPEM, _, _ := provision.IssueClientCert(caCert, caKey, "bob@corp", "eng")
	id, err := identity.FromClientCert(leafFromPEM(t, certPEM))
	if err != nil {
		t.Fatal(err)
	}
	ctx := id.Context()
	if ctx.Identity == "" || ctx.Role != "eng" {
		t.Errorf("context = %+v, want identity set and role eng", ctx)
	}
	if ctx.DevicePosture.HasPosture {
		t.Error("Context() set HasPosture true — posture is a separate producer; a cert-authenticated " +
			"but unattested device must fail closed under D85")
	}
}
