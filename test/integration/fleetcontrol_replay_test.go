//go:build integration

package integration

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// SEC-B, end to end: a fleet-wide DISABLE captured off the wire must not work again after the host
// restarts.
//
// The unit tests pin the bound; this pins the WIRING, which is where the defect actually lived. The
// replay refusal was correct code the whole time — it just consulted a `uint64` that a new process
// initialised to zero, and no binary gave it anywhere to persist. Every unit test passed.
//
// The scenario runs the real attack: subscribe to the control subject, keep the exact bytes the control
// plane published, restart the gateway, and send those same bytes again. Nothing is forged and nothing is
// modified — the signature, the version and the TTL are all genuinely valid, which is what makes replay
// the sharp case.
//
// It asserts on BOTH sides of the bound, in one run:
//
//   - a gateway with a persisted bound refuses the replay and stays enforcing;
//   - a gateway told to keep its bound in memory ACCEPTS it and stops enforcing.
//
// The second is not decoration. Without it, a mistake anywhere in the fixture — the wrong subject,
// unsigned bytes, a control that had already expired — would produce "the replay did nothing" for
// reasons having nothing to do with the bound, and the test would pass while proving nothing. The
// in-memory host is the control group that shows the captured bytes really are live ammunition.
func TestACapturedFleetDisableDoesNotSurviveARestart(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	privPath, pubPath := signingKeypair(t)

	// Capture what the control plane publishes. A raw subscriber is the attacker's position: anyone who
	// can read the subject holds a replayable control until its TTL.
	conn, err := nats.Connect(stack.NATSURL)
	if err != nil {
		t.Fatalf("nats: %v", err)
	}
	defer conn.Close()
	var mu sync.Mutex
	var captured [][]byte
	sub, err := conn.Subscribe(natsx.SubjectFleetControl, func(m *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, append([]byte(nil), m.Data...))
	})
	if err != nil {
		t.Fatalf("subscribing to the fleet-control subject: %v", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// One host's state directory, shared by the process before the restart and the one after — which is
	// what makes the second process the SAME host rather than a new one. The signer state has to travel
	// with it for an unrelated reason worth recording: a gateway that mints a fresh ledger signer cannot
	// continue a hash chain another signer started, so without this the restarted process refuses to open
	// its ledger and never reaches the code under test.
	hostState := t.TempDir()
	seqFile := filepath.Join(hostState, "fleet-control.seq")
	gwEnv := func(bound, dsn, state string) []string {
		return []string{
			"OPENSHIELD_DSN=" + dsn,
			"OPENSHIELD_SIGNER_FILE=" + filepath.Join(state, "gateway-signer.state"),
			"OPENSHIELD_NATS_URL=" + stack.NATSURL,
			"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
			"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
			"OPENSHIELD_ENFORCE=1",
			"OPENSHIELD_CONTROL_PLANE_KEY=" + pubPath,
			"OPENSHIELD_FLEET_CONTROL_SEQ_FILE=" + bound,
			// The degraded-counter line is reported on a ticker, once a minute by default. Shortened so
			// the scenario can assert the refusal was COUNTED without waiting out a production cadence.
			"OPENSHIELD_DISCARD_REPORT_INTERVAL=2s",
			"OPENSHIELD_BREAK_GLASS=" + filepath.Join(t.TempDir(), "EMERGENCY_DISABLE"),
		}
	}

	gw := Start(t, "openshield-gateway", gwEnv(seqFile, stack.DSN, hostState))
	gw.WaitForOutput("fleet-wide enforcement control ACTIVE", 90*time.Second)

	// Issue a real, four-eyes-approved disable.
	out, err := runCapture(t, "openshield-server",
		[]string{"OPENSHIELD_DSN=" + stack.DSN}, "fleet-control", "prepare", "disable", "integration")
	if err != nil {
		t.Fatalf("preparing a fleet control: %v\n%s", err, out)
	}
	controlID := firstLine(out)
	approveFleetControl(t, stack, controlID)
	// A LONG TTL, because expiry is the other bound and this scenario is about the replay one. With a
	// short TTL the replay would be refused as expired and the test would pass without the fix.
	out, err = runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_RISK_SIGNING_KEY=" + privPath,
	}, "fleet-control", "publish", controlID, "integration", "24h")
	if err != nil {
		t.Fatalf("publishing an approved fleet disable: %v\n%s", err, out)
	}
	gw.WaitForOutput("ENFORCEMENT DISABLED", 60*time.Second)

	Eventually(t, 30*time.Second, "the control plane's published bytes to arrive", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(captured) > 0
	})
	mu.Lock()
	replay := captured[0]
	mu.Unlock()

	// THE RESTART. Gracefully, so it is the ordinary restart an attacker waits for — a package upgrade, a
	// reboot, a crash loop — rather than anything unusual.
	gw.Stop()

	restarted := Start(t, "openshield-gateway", gwEnv(seqFile, stack.DSN, hostState))
	restarted.WaitForOutput("fleet-wide enforcement control ACTIVE", 90*time.Second)
	// It comes up ENFORCING: the kill switch itself is not persisted, only the replay bound is. That is
	// what makes the replay worth doing, and it is also why the assertion below is unambiguous — any
	// "ENFORCEMENT DISABLED" printed by this process came from the replayed control.
	if contains(restarted.Output(), "ENFORCEMENT DISABLED") {
		t.Fatalf("the restarted gateway came up already disabled — the fixture cannot distinguish the "+
			"replay from persisted switch state\n%s", restarted.Output())
	}

	if err := conn.Publish(natsx.SubjectFleetControl, replay); err != nil {
		t.Fatalf("replaying the captured control: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}

	// The control group: a gateway that keeps its bound in memory, started AFTER the capture and given
	// the identical bytes. If this one does not disable, the ammunition is blank and the assertion above
	// proves nothing.
	inMemory := Start(t, "openshield-gateway", gwEnv("", stack.DSNFor(t, "inmemory"), t.TempDir()))
	inMemory.WaitForOutput("replay bound is IN MEMORY", 90*time.Second)
	inMemory.WaitForOutput("fleet-wide enforcement control ACTIVE", 90*time.Second)
	if err := conn.Publish(natsx.SubjectFleetControl, replay); err != nil {
		t.Fatalf("replaying to the in-memory gateway: %v", err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	inMemory.WaitForOutput("ENFORCEMENT DISABLED", 60*time.Second)

	// Both hosts have now had the same bytes for at least as long as the in-memory one needed to act on
	// them, so a still-enforcing gateway is a refusal rather than a race.
	if contains(restarted.Output(), "ENFORCEMENT DISABLED") {
		t.Errorf("a fleet-wide DISABLE captured before a restart stopped enforcement after it. The "+
			"replay bound reset to zero on boot, so waiting for a reboot is all an attacker has to do "+
			"to re-run any control they have ever seen\n%s", restarted.Output())
	}
	// PROVE THE CHANNEL IS LIVE TO THIS PROCESS, or everything above is unfalsifiable.
	//
	// "The restarted gateway did not disable" has two explanations and only one of them is the fix: the
	// bound refused the replay, or the message never arrived. A subscriber that silently stopped
	// receiving would produce an identical, passing test — and the counter that would have distinguished
	// them is reported on a ticker that only fires when it moves, so its absence is not evidence either.
	//
	// A FRESH, legitimately-issued control settles it. It travels the same subject to the same
	// subscriber, and it must be applied. That also covers the failure mode this fix could plausibly
	// introduce and which would be far worse than the bug: a persisted bound set too high, or never
	// advanced past a stale value, leaves a host that can never be told to stop enforcing again.
	out, err = runCapture(t, "openshield-server",
		[]string{"OPENSHIELD_DSN=" + stack.DSN}, "fleet-control", "prepare", "disable", "second incident")
	if err != nil {
		t.Fatalf("preparing a second fleet control: %v\n%s", err, out)
	}
	secondID := firstLine(out)
	approveFleetControl(t, stack, secondID)
	out, err = runCapture(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_RISK_SIGNING_KEY=" + privPath,
	}, "fleet-control", "publish", secondID, "second incident", "24h")
	if err != nil {
		t.Fatalf("publishing a second approved fleet disable: %v\n%s", err, out)
	}
	restarted.WaitForOutput("second incident", 60*time.Second)

	// And the refusal was COUNTED. Asserted only now, because the applied control above guarantees the
	// degraded line fires — it reports on movement, so a rejection alone can sit unreported until
	// something else moves. A refusal nobody can see is indistinguishable from a channel that went quiet,
	// and this is the one channel whose silence an operator must not have to guess about (D31).
	Eventually(t, 60*time.Second, "the refused replay to be reported as a rejection", func() bool {
		for _, line := range strings.Split(restarted.Output(), "\n") {
			if strings.Contains(line, "fleet_control_rejected=") &&
				!strings.Contains(line, "fleet_control_rejected=0") {
				return true
			}
		}
		return false
	})
}
