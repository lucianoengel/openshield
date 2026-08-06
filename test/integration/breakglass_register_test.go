//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// CONSOLE-8 AGAINST THE SHIPPED BINARIES.
//
// The register's ONLY writer is reached from `cmd/openshield-server fleet-control publish`. A package
// test can seed the table and assert every derivation over it, and still prove nothing about whether
// issuing a real control writes a row — which is the entire ticket. That is the shape this repo has now
// found six times (D313, D415, D417, D418, D470, and CONSOLE-1's `/report/response`): a field only tests
// write.
//
// So this scenario issues a REAL approved fleet disable through the real CLI, against a real broker, and
// then asks the operator API the question a CISO asks: since when, by whom, until when, and why.

func TestABreakGlassDisableIsIssuedByOneBinaryAndReadableFromAnother(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)
	privPath, _ := signingKeypair(t)

	addr := "127.0.0.1:" + freePort(t)
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 60*time.Second)

	analyst := p.operator(t, "analyst", "fleet-watcher")

	// BEFORE: nothing has ever stopped this fleet, and the surface says exactly that rather than
	// reporting an unknown state or refusing.
	before := readRegister(t, analyst, addr)
	if before.Suppressed {
		t.Fatalf("a fresh deployment reports enforcement as suppressed: %+v", before)
	}
	if len(before.Controls) != 0 {
		t.Fatalf("a fresh register is not empty: %+v", before.Controls)
	}

	// Issue one for real, through the two-step path: prepare allocates the id, two operators approve it,
	// publish sends it. This is the operator's actual workflow, not a seeded row.
	out, err := runCapture(t, "openshield-server",
		[]string{"OPENSHIELD_DSN=" + stack.DSN}, "fleet-control", "prepare", "disable", "incident 41")
	if err != nil {
		t.Fatalf("preparing a fleet control: %v\n%s", err, out)
	}
	controlID := firstLine(out)
	if !strings.HasPrefix(controlID, "fleet:") {
		t.Fatalf("prepare printed no control id:\n%s", out)
	}
	approveFleetControl(t, stack, controlID)
	// The publish leg needs the broker's TLS material too — this stack's NATS is mutually authenticated,
	// and a control that cannot reach the broker is never recorded either (the write aborts the publish).
	if out, err = runCapture(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_RISK_SIGNING_KEY=" + privPath,
	}, tlsEnv(m)...), "fleet-control", "publish", controlID, "incident 41", "2h"); err != nil {
		t.Fatalf("an APPROVED fleet disable was refused: %v\n%s", err, out)
	}

	// AFTER: the whole question, answered over HTTP by a different process than the one that issued it.
	after := readRegister(t, analyst, addr)
	if !after.Suppressed {
		t.Fatalf("a disable was published seconds ago and the surface says the fleet is enforcing: %+v\n"+
			"Either the control was never recorded, or recordFleetControl is not called by the binary — "+
			"and the second is a writer that only tests exercise", after)
	}
	if len(after.Controls) != 1 {
		t.Fatalf("register holds %d controls after one publish: %+v", len(after.Controls), after.Controls)
	}
	c := after.Controls[0]

	if c.ControlID != controlID {
		t.Errorf("register holds %q, want the published id %q", c.ControlID, controlID)
	}
	if !c.Standing {
		t.Error("the only unexpired control is not reported as standing")
	}
	// SINCE WHEN and UNTIL WHEN. Both travelled on the wire to every endpoint and were, until this
	// change, discarded the moment the message was marshalled.
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		t.Fatalf("issued_at=%v expires_at=%v — an operator who finds the product off cannot tell when it "+
			"comes back", c.IssuedAt, c.ExpiresAt)
	}
	if d := c.ExpiresAt.Sub(c.IssuedAt); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("recorded TTL = %v, want the 2h the CLI published — a register that recomputes the "+
			"expiry can disagree with the endpoints about when protection returns", d)
	}
	// BY WHOM. Joined from the four-eyes approval, which is the identity that was actually verified.
	if c.Requester == nil || c.Approver == nil {
		t.Fatalf("requester=%v approver=%v — the register cannot name who suppressed enforcement",
			c.Requester, c.Approver)
	}
	if *c.Requester == *c.Approver {
		t.Errorf("requester and approver are the same identity (%q) — four eyes were one pair", *c.Requester)
	}
	// AND WHY.
	if c.Reason == "" {
		t.Error("the operator's justification did not survive to the register")
	}

	// The roster is reachable and AGREES about suppression. An operator reads the two together, and two
	// surfaces that can contradict each other about whether the product is on are worse than one.
	roster := readRoster(t, analyst, addr)
	if !roster.Suppressed {
		t.Errorf("the roster says the fleet is enforcing while the register says it is suppressed — an "+
			"operator reading both cannot act on either: %+v", roster)
	}
	if roster.TargetSequence == 0 {
		t.Errorf("target_sequence = 0 after a control was published, so no agent could ever be reported "+
			"as behind: %+v", roster)
	}
}

type registerBody struct {
	Suppressed bool `json:"suppressed"`
	Controls   []struct {
		ControlID string    `json:"control_id"`
		Verb      string    `json:"verb"`
		Sequence  uint64    `json:"sequence"`
		IssuedAt  time.Time `json:"issued_at"`
		ExpiresAt time.Time `json:"expires_at"`
		Reason    string    `json:"reason"`
		Standing  bool      `json:"standing"`
		Requester *string   `json:"requester"`
		Approver  *string   `json:"approver"`
	} `json:"controls"`
}

type rosterBody struct {
	Suppressed     bool   `json:"suppressed"`
	TargetSequence uint64 `json:"target_sequence"`
	Agents         []struct {
		AgentID  string     `json:"agent_id"`
		LastSeen *time.Time `json:"last_seen"`
	} `json:"agents"`
}

func readRegister(t *testing.T, c *http.Client, addr string) registerBody {
	t.Helper()
	var out registerBody
	getOperatorJSON(t, c, "https://"+addr+"/fleet/controls", &out)
	return out
}

func readRoster(t *testing.T, c *http.Client, addr string) rosterBody {
	t.Helper()
	var out rosterBody
	getOperatorJSON(t, c, "https://"+addr+"/fleet", &out)
	return out
}

func getOperatorJSON(t *testing.T, c *http.Client, url string, into any) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("parsing %s: %v\n%s", url, err, body)
	}
}
