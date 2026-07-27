package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucianoengel/openshield/internal/provision"
	canonid "github.com/lucianoengel/openshield/internal/pseudonym"
)

// THE PER-AGENT POSTURE ROSTER (D315).
//
// SEC-12 replaced a single shared posture-signing key with a ROSTER: every agent signs its own posture
// with its own key, and the gateway verifies each against that agent's enrolled public key. The reason is
// concrete — with one shared key, any agent could forge any other agent's `Compliant=true`, which makes
// the posture signal worth nothing precisely when it matters (one compromised endpoint vouching for
// itself as another).
//
// The gateway has READ that roster since SEC-12 and NOTHING COULD WRITE ONE. `posture-keygen` still
// produced the superseded shape — one keypair, "posture-pub (to gateways)" — which does not fit the
// roster format at all, and its message told operators to install it as `OPENSHIELD_POSTURE_PUBKEY`, a
// variable the gateway no longer reads. An operator following the tool's own instructions ended up with
// a deployment whose posture channel was inert, and the only warning was a startup line.
//
// So this is the third instance of one shape in as many rounds: A READER WITH NO WRITER. The enrollments
// file had it, the interception CA has it, and this had it while ALSO shipping a tool that produced the
// wrong thing confidently.
//
// APPENDING, NOT REWRITING, and per agent: a fleet is enrolled one machine at a time, and a command that
// truncated the roster would silently un-enrol every other agent. Because unenrolled posture is never
// applied, that surfaces as "the fleet lost its posture signal after we added a laptop" — a long way from
// the cause.

const postureEnrollUsage = `usage:
  openshield-provision posture-enroll --agent AGENT_ID --roster FILE --out DIR
      generate this agent's posture signing key and add it to the gateway's roster
`

func postureEnroll(f map[string][]string) int {
	agent, roster, out := one(f, "agent"), one(f, "roster"), one(f, "out")
	if agent == "" || roster == "" || out == "" {
		fmt.Fprint(os.Stderr, postureEnrollUsage)
		return 2
	}
	pub, priv, err := provision.WitnessKeypair()
	if err != nil {
		return fail("generating the posture keypair: %v", err)
	}

	// The roster is READ BACK FIRST and re-enrolling an agent REPLACES its line rather than adding a
	// second one. Two lines for one agent would mean the resolver silently picks whichever the loader
	// saw last — a key rotation that half-worked, which is worse than one that failed.
	lines, err := rosterLines(roster, agent)
	if err != nil {
		return fail("%v", err)
	}
	lines = append(lines, agent+" "+base64.StdEncoding.EncodeToString(pub))
	if err := writeFile(roster, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return fail("writing %s: %v", roster, err)
	}
	// 0600 on the private key: it is what lets this agent make a posture claim the gateway believes.
	if err := writeFile(filepath.Join(out, "posture-priv"), priv, 0o600); err != nil {
		return fail("writing the agent's key: %v", err)
	}

	fmt.Fprintf(os.Stderr, "openshield-provision: enrolled %s in %s (%d agent(s) now)\n",
		agent, roster, len(lines))
	fmt.Fprintf(os.Stderr, "openshield-provision: give %s/posture-priv to THAT AGENT ONLY, as "+
		"OPENSHIELD_POSTURE_SIGNING_KEY. Sharing one key across agents is the exact failure SEC-12's "+
		"roster exists to prevent: any holder can forge any other agent's posture.\n", out)
	// The pseudonym is printed because it is the name everything downstream uses — the subject the agent
	// publishes under and the key the gateway resolves. An operator debugging "posture is not applied"
	// needs to be able to line these up, and the raw agent id never appears on the wire (ADR-6/IDENT-1).
	fmt.Fprintf(os.Stderr, "openshield-provision: this agent's canonical subject is %s\n", canonid.Of(agent))
	return 0
}

// rosterLines reads the existing roster, dropping any line for the agent being enrolled.
//
// A MALFORMED ROSTER IS A REFUSAL, not something to silently rewrite: the gateway aborts startup on a bad
// roster line, so a command that quietly dropped the lines it could not parse would produce a file that
// loads — having removed agents whose absence nobody chose.
func rosterLines(path, agent string) ([]string, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(blob), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s has a line the gateway will refuse to load: %q "+
				"(want '<agent-id> <base64-pubkey>'). Fix or remove it — rewriting the file around it "+
				"would drop agents nobody chose to unenrol", path, trimmed)
		}
		if fields[0] == agent {
			continue // re-enrolment replaces
		}
		out = append(out, line)
	}
	return out, nil
}
