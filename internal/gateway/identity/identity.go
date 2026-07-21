// Package identity resolves a verified client certificate into a Zero-Trust subject
// (D86): a pseudonymous identity + an authorization-group role, ready to place in the
// pipeline Context (D85). It is the PRODUCER that fills the identity contract,
// replacing the sha256(src-IP) non-identity (D77/D84) that made "Zero Trust" an
// overclaim.
//
// The access-proxy mode (proposal §5.1, a later increment) calls FromClientCert per
// connection to set the Event subject and resolve the Context. Client-cert auth only
// here; OIDC/bearer is a noted follow-up (A.2b).
package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/provision"
)

// Identity is a resolved, verified Zero-Trust subject. Subject is pseudonymous (D23)
// — the raw certificate identity is hashed one-way and never carried here or into the
// pipeline. Role is the authorization group (e.g. "finance"), an authorization class,
// not personally identifying, so it is carried in the clear (a policy needs it).
type Identity struct {
	Subject string
	Role    string
}

// FromClientCert verifies that a certificate is a CLIENT cert (D86) and resolves it
// into an Identity. It requires the RoleClient marker in the OU — an agent, operator,
// or unknown certificate is NOT a client identity and is rejected (the D58 discipline:
// the role is on the cert, verified, never inferred). The caller is responsible for
// having already verified the cert against the CA at the TLS layer; this reads the
// verified leaf's subject.
func FromClientCert(leaf *x509.Certificate) (*Identity, error) {
	if leaf == nil {
		return nil, fmt.Errorf("identity: no certificate")
	}
	if !hasClientRole(leaf) {
		return nil, fmt.Errorf("identity: certificate is not a client certificate (OU %v, want %q)",
			leaf.Subject.OrganizationalUnit, provision.RoleClient)
	}
	cn := leaf.Subject.CommonName
	if cn == "" {
		return nil, fmt.Errorf("identity: client certificate has no identity (empty CommonName)")
	}
	group := ""
	if len(leaf.Subject.Organization) > 0 {
		group = leaf.Subject.Organization[0]
	}
	if group == "" {
		return nil, fmt.Errorf("identity: client certificate has no authorization group (empty Organization)")
	}
	return &Identity{Subject: pseudonym(cn), Role: group}, nil
}

// Context builds the pipeline Context for this identity (D85). Device posture is left
// ABSENT (HasPosture=false) — posture is a separate producer, and a ZT access policy
// denies on absent posture, so a cert-authenticated but unattested device still fails
// closed. Authentication is not device trust.
func (id *Identity) Context() *core.Context {
	return &core.Context{
		Identity:      id.Subject,
		Role:          id.Role,
		DevicePosture: core.DevicePosture{HasPosture: false},
	}
}

func hasClientRole(leaf *x509.Certificate) bool {
	for _, ou := range leaf.Subject.OrganizationalUnit {
		if ou == provision.RoleClient {
			return true
		}
	}
	return false
}

// pseudonym one-way-hashes the raw identity so it never enters the pipeline (D23).
// The reverse mapping (pseudonym → real identity) is a deployer concern behind an
// audited lookup (D23/D47).
func pseudonym(identity string) string {
	sum := sha256.Sum256([]byte("zt-client-subject:" + identity))
	return "sub_" + hex.EncodeToString(sum[:12])
}
