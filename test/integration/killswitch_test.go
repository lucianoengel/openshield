//go:build integration

package integration

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE EMERGENCY DISABLE, end to end (PLAT-9).
//
// "How do I stop this?" is the question a CISO asks before "what does it detect?", and it is the one
// question a security product must be able to answer without being uninstalled — because stopping the
// process also stops the detection and the audit trail, the worst possible trade during an incident the
// product itself is causing.
//
// Every piece of this existed and was tested before these scenarios: the kill switch, the break-glass
// watcher, the signed fleet-control channel with its four-eyes gate, replay bound and TTL. NOT ONE OF
// THEM WAS REACHABLE FROM A SHIPPED BINARY. No command installed a KillSwitch, so the gateway's and
// engine's switch fields were nil; no command called SubscribeFleetControl, so the channel had no
// consumer; no command called SetIntentSigner, so the control plane could not sign a control even if
// something had asked it to; and PublishFleetControl had no caller at all. A feature whose every unit
// passes and whose every path is unreachable is indistinguishable, from outside, from one that was never
// built — and worse, because the tests say it works.
//
// These scenarios are the wiring, asserted the only way wiring can be: by running the real binaries.

// signingKeypair writes a raw ed25519 private key and its public half, and returns both paths.
//
// Raw bytes rather than PEM because that is what the loaders take, and the length check they perform is
// the reason: a wrong-format key file would otherwise become a subscriber that verifies nothing and
// refuses everything, which from the outside looks exactly like a quiet channel.
func signingKeypair(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privPath = filepath.Join(dir, "signing.key")
	pubPath = filepath.Join(dir, "signing.pub")
	if err := os.WriteFile(privPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return privPath, pubPath
}

// approveFleetControl records an APPROVED four-eyes approval for a control id, the way two operators
// would through the console.
//
// Two distinct identities, because that is the whole content of "four eyes": an approval resolved by its
// own requester authorizes nothing.
func approveFleetControl(t *testing.T, stack *Stack, controlID string) {
	t.Helper()
	pool := openPool(t, stack.DSN)
	if _, err := pool.Exec(Ctx(t),
		`INSERT INTO approvals (subject_kind, subject_id, requester, reason, state, approver, resolved_at, expires_at)
		 VALUES ('fleet-control',$1,'operator:alice','integration','approved','operator:bob', now(), now() + interval '1 hour')`,
		controlID); err != nil {
		t.Fatalf("approving %s: %v", controlID, err)
	}
}

// TestAFleetWideDisableReachesAGatewayAndStopsEnforcement is the round trip: an operator issues the
// control, and a RUNNING gateway stops enforcing.
func TestAFleetWideDisableReachesAGatewayAndStopsEnforcement(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	privPath, pubPath := signingKeypair(t)

	// A gateway that trusts this control plane's key. OPENSHIELD_BREAK_GLASS points into a temp dir so
	// the scenario cannot be affected by — or affect — a real /etc/openshield file on this machine.
	gwEnv := []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_ENFORCE=1",
		"OPENSHIELD_CONTROL_PLANE_KEY=" + pubPath,
		"OPENSHIELD_BREAK_GLASS=" + filepath.Join(t.TempDir(), "EMERGENCY_DISABLE"),
	}
	gw := Start(t, "openshield-gateway", gwEnv)
	gw.WaitForOutput("fleet-wide enforcement control ACTIVE", 90*time.Second)

	// An ENDPOINT on the same channel, and deliberately NOT enrolled: being able to be disabled must not
	// depend on being able to publish telemetry. An endpoint that failed to enrol is not the one that
	// should be impossible to stop.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSNFor(t, "endpoint"),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_ENFORCE=1",
		"OPENSHIELD_CONTROL_PLANE_KEY=" + pubPath,
		"OPENSHIELD_BREAK_GLASS=" + filepath.Join(t.TempDir(), "EMERGENCY_DISABLE"),
	})
	eng.WaitForOutput("fleet-wide enforcement control ACTIVE", 90*time.Second)

	// Step 1: allocate the control id. The four-eyes approval is bound to THIS id, so it has to exist
	// before anyone can approve it — which is why issuing is two steps rather than one.
	out, err := runCapture(t, "openshield-server",
		[]string{"OPENSHIELD_DSN=" + stack.DSN}, "fleet-control", "prepare", "disable", "integration")
	if err != nil {
		t.Fatalf("preparing a fleet control: %v\n%s", err, out)
	}
	controlID := firstLine(out)
	if !strings.HasPrefix(controlID, "fleet:") {
		t.Fatalf("prepare printed no control id:\n%s", out)
	}

	// UNAPPROVED FIRST. A disable that publishes without four eyes is not gated, and asserting only the
	// happy path would not notice.
	out, err = runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_RISK_SIGNING_KEY=" + privPath,
	}, "fleet-control", "publish", controlID, "integration", "1h")
	if err == nil {
		t.Fatalf("an UNAPPROVED fleet disable was published — there is no low-impact way to disable a "+
			"security product fleet-wide, so this gate has no exception:\n%s", out)
	}

	// Step 2: two operators approve, and it publishes.
	approveFleetControl(t, stack, controlID)
	out, err = runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_RISK_SIGNING_KEY=" + privPath,
	}, "fleet-control", "publish", controlID, "integration", "1h")
	if err != nil {
		t.Fatalf("an APPROVED fleet disable was refused: %v\n%s", err, out)
	}

	// THE ASSERTION THAT MATTERS, and it is made against BOTH components. core.KillSwitch's first stated
	// property is that a switch honoured by the gateway and forgotten by the endpoint is worse than none,
	// because the operator believes enforcement stopped and it did not. A scenario that checked only one
	// of them would be the same omission, one level up.
	gw.WaitForOutput("ENFORCEMENT DISABLED", 60*time.Second)
	eng.WaitForOutput("ENFORCEMENT DISABLED", 60*time.Second)

	// And it is still running. "Stop acting, keep seeing" is the entire design: a kill switch that takes
	// the process down would destroy the record of what happened while enforcement was off — exactly the
	// period an operator needs to reconstruct.
	if gw.Cmd.ProcessState != nil {
		t.Errorf("the gateway EXITED on a fleet disable. The switch sits between the decision and the "+
			"enforcer so detection and audit continue; a disable that stops the process is the trade this "+
			"feature exists to avoid\n%s", gw.Output())
	}
}

// TestTheLocalBreakGlassFileStopsEnforcement is the path that works when the control plane does not.
//
// It is the more important of the two, and the easier to leave unwired: the fleet channel needs a broker,
// a key and a reachable control plane — precisely the things that are gone during the incident where an
// operator most needs to stop enforcement on one host.
func TestTheLocalBreakGlassFileStopsEnforcement(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	glass := filepath.Join(t.TempDir(), "EMERGENCY_DISABLE")

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_ENFORCE=1",
		"OPENSHIELD_BREAK_GLASS=" + glass,
		"OPENSHIELD_BREAK_GLASS_POLL=200ms",
		// No NATS and no control-plane key: this is the isolated host.
	})
	// Give the engine time to come up and take its first reading of an ABSENT file. Absence must mean
	// disengaged — it is the normal state, and cannot be allowed to mean "stop enforcing".
	time.Sleep(3 * time.Second)
	if contains(eng.Output(), "ENFORCEMENT DISABLED") {
		t.Fatalf("enforcement was disabled with NO break-glass file present. The switch fails toward "+
			"ENFORCING: absence is never engagement, or a permissions change silently turns the product "+
			"off across a fleet\n%s", eng.Output())
	}

	if err := os.WriteFile(glass, []byte("incident 41\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng.WaitForOutput("ENFORCEMENT DISABLED", 60*time.Second)
	// The operator's own words come back, so the log answers WHY rather than only THAT.
	if !contains(eng.Output(), "incident 41") {
		t.Errorf("the reason written in the break-glass file is not in the notice — an operator reading "+
			"the log cannot tell a deliberate disable from an accident\n%s", eng.Output())
	}

	// Removing it restores enforcement, and says so. A switch that cannot be un-flipped is not a switch.
	if err := os.Remove(glass); err != nil {
		t.Fatal(err)
	}
	eng.WaitForOutput("enforcement RESTORED", 60*time.Second)
}

// firstLine returns the first non-empty line — how the subcommands print a single value.
func firstLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(l); s != "" {
			return s
		}
	}
	return ""
}
