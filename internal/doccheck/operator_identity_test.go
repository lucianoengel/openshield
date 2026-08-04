package doccheck_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// CONSOLE-1: ONE PLACE DECIDES WHO IS CALLING.
//
// The defect this guards against already shipped once. `requireTier` authenticated a client certificate
// OR an OIDC bearer token, then dropped the answer; eight handlers re-derived the operator from
// `r.TLS`, which is empty for a bearer request. So an SSO operator passed the authorization gate and was
// refused by every handler that needed their name — two authentications, by two different rules, in one
// request, disagreeing.
//
// The fix removed the second rule: `operatorIdentity` lost its `*tls.ConnectionState` argument and reads
// the principal the gate put on the request context. The compiler found all eight call sites, and it
// will find any new one written the same way.
//
// WHAT THE COMPILER WILL NOT FIND is a handler that reaches for `r.TLS` DIRECTLY — a new
// `r.TLS.PeerCertificates[0].Subject.CommonName`, written by someone who has a request in hand and
// wants a name from it. That compiles perfectly, works under a certificate, and silently fails under
// SSO. This is the check for that, and it is a grep because the property is syntactic: no operator
// handler may consult the transport for an identity.

// tlsIdentityAllowed lists the two functions that may legitimately read the TLS state, by the file that
// holds them. Both are AUTHENTICATION, not attribution — the distinction the split above rests on.
var tlsIdentityAllowed = map[string]string{
	// authenticateOperator: the certificate path of the gate itself. Somewhere has to turn a verified
	// peer into a principal, and this is that place.
	"operator_roles.go": "authenticateOperator, the certificate half of the one gate",
	// requireRole: the exact-role gate used only for `agent`, which is not an operator tier and has no
	// row in operator_roles. An agent's role is a property of the credential the fleet was issued.
	"views.go": "requireRole, the agent-only certificate gate",
}

func TestNoOperatorHandlerDerivesAnIdentityFromTheTransport(t *testing.T) {
	dir := filepath.Join("..", "controlplane")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	var scanned, allowedSeen int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		var hits int
		for _, line := range strings.Split(string(body), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if strings.Contains(code, "r.TLS") {
				hits++
			}
		}
		if hits == 0 {
			continue
		}
		if _, ok := tlsIdentityAllowed[name]; ok {
			allowedSeen++
			continue
		}
		offenders = append(offenders, name)
	}

	if scanned < 10 {
		t.Fatalf("scanned only %d control-plane sources — this guard is looking in the wrong place and "+
			"proves nothing", scanned)
	}
	// THE ALLOWLIST MUST STILL MATCH SOMETHING. If both authenticating functions were renamed or moved,
	// an empty allowlist would keep passing while guarding nothing — the shape of a check that outlived
	// the code it checks.
	if allowedSeen != len(tlsIdentityAllowed) {
		t.Errorf("%d of %d allowlisted files still read r.TLS — if authentication moved, move the "+
			"allowlist with it rather than leaving a guard that matches nothing",
			allowedSeen, len(tlsIdentityAllowed))
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("these control-plane sources read r.TLS outside the authentication gate: %v\n"+
			"A handler that derives an operator from the transport answers correctly for a certificate "+
			"and 401 for a bearer token that already passed authorization — the CONSOLE-1 defect, "+
			"reintroduced. Read the principal from the request context with operatorIdentity(r.Context()).",
			offenders)
	}
}
