//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// The TRUST BOOTSTRAP, end to end.
//
// This is the seam most worth running for real, because it spans four components and every one of them
// can pass its own tests while the chain is broken: an operator issues a single-use token, an agent
// enrols with it and receives an identity, the agent signs its telemetry with that identity, and the
// control plane verifies the signature before storing anything as evidence (D44).
//
// The property that matters is not "telemetry arrives" — it is that telemetry arrives VERIFIED. Unsigned
// or unenrolled telemetry reaching the aggregate as evidence would undermine every downstream claim, and
// nothing short of running the real binaries against a real broker proves it does not.

// issueToken runs the operator-local subcommand and returns the token.
//
// A subcommand, not a route (D51): an unauthenticated mint endpoint would defeat the single-use model
// entirely, so this is exercised the way an operator actually does it.
func issueToken(t *testing.T, stack *Stack, agentID string) string {
	t.Helper()
	out, err := runCapture(t, "openshield-server",
		[]string{"OPENSHIELD_DSN=" + stack.DSN}, "issue-token", agentID)
	if err != nil {
		t.Fatalf("issuing an enrollment token: %v\n%s", err, out)
	}
	// The token is the last non-empty line the command prints.
	var token string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if l := strings.TrimSpace(line); l != "" {
			token = l
		}
	}
	if token == "" {
		t.Fatalf("no token in the subcommand output:\n%s", out)
	}
	return token
}

// startServer brings up the control plane with its HTTP surface, and waits until it is actually serving.
func startServer(t *testing.T, stack *Stack, extraEnv ...string) (*Process, string) {
	t.Helper()
	addr := "127.0.0.1:" + freePort(t)
	env := append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, extraEnv...)
	srv := Start(t, "openshield-server", env)
	waitTCP(t, addr, 60*time.Second)
	return srv, "http://" + addr + "/enroll"
}

// TestEnrolledAgentTelemetryIsStoredVERIFIED is the acceptance case for the trust bootstrap.
func TestEnrolledAgentTelemetryIsStoredVerified(t *testing.T) {
	stack := StartStack(t)
	srv, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)

	token := issueToken(t, stack, "agent-integration-1")
	Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-integration-1",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_SUBJECT=subject-integration-1",
		"OPENSHIELD_HEARTBEAT=200ms",
	})

	// VERIFIED is the assertion. Storing telemetry is easy; storing it as attributable evidence is the
	// claim everything downstream rests on.
	Eventually(t, 90*time.Second, "verified telemetry from the enrolled agent", func() bool {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-integration-1' AND verified`).
			Scan(&n); err != nil {
			return false
		}
		return n > 0
	})

	// And nothing from this agent landed UNVERIFIED — a mixed result would mean the verifying path is
	// racing an unverified one, which is worse than a clean failure because it looks fine in aggregate.
	var unverified int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-integration-1' AND NOT verified`).
		Scan(&unverified); err != nil {
		t.Fatal(err)
	}
	if unverified > 0 {
		t.Errorf("%d row(s) from an ENROLLED agent were stored unverified — attributability is not "+
			"something the aggregate may have some of\n%s", unverified, srv.Output())
	}
}

// TestUnsignedTelemetryIsNeverStoredAsEvidence is the other half, and the one that decides whether the
// first half means anything.
//
// IT PUBLISHES DIRECTLY TO NATS rather than running an unenrolled agent, and that distinction is the
// whole point. My first version started the agent binary with no enrollment and asserted no verified rows
// appeared — which PASSED VACUOUSLY: that agent publishes NOTHING at all without an identity, so the test
// proved "our binary declines to send" rather than "the control plane declines to trust". An attacker
// does not use our binary. Publishing raw onto the subject is the realistic shape.
//
// Unsigned telemetry may legitimately be STORED (the legacy self-asserted path, D41) — what it must never
// be is VERIFIED, because verified is what makes a row attributable evidence (D44).
func TestUnsignedTelemetryIsNeverStoredAsEvidence(t *testing.T) {
	stack := StartStack(t)
	srv, _ := startServer(t, stack)
	pool := openPool(t, stack.DSN)

	tr, err := natsx.Connect(stack.NATSURL)
	if err != nil {
		t.Fatalf("connecting to the stack broker: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	const forgedAgent = "agent-forged"
	ev := &corev1.Event{
		EventId: "forged-1", AgentId: forgedAgent,
		Kind:       corev1.EventKind_EVENT_KIND_NETWORK_FLOW,
		ObservedAt: timestamppb.New(time.Now()),
		Subject:    &corev1.Subject{PseudonymousId: "subject-forged"},
		Target:     &corev1.Event_Network{Network: &corev1.NetworkSubject{SniHost: "attacker.example"}},
	}
	// PublishEvent is the UNSIGNED path: no envelope, no identity, no enrollment. It is what anything
	// that can reach the broker can do, which is the threat this must hold against.
	for i := 0; i < 20; i++ {
		ev.EventId = fmt.Sprintf("forged-%d", i)
		if err := tr.PublishEvent(Ctx(t), ev); err != nil {
			t.Fatalf("publishing forged telemetry: %v", err)
		}
	}
	time.Sleep(3 * time.Second)

	// FIRST: prove the forged telemetry ARRIVED. Without this the test can silently become vacuous —
	// which is exactly what happened to its first version, where nothing was ever published and "no
	// verified rows" was true because there were no rows at all.
	var total int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id=$1`, forgedAgent).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total == 0 {
		t.Fatalf("no forged telemetry reached the control plane at all — this test then proves nothing "+
			"about whether it would be TRUSTED\n%s", srv.Output())
	}

	var verified int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id=$1 AND verified`, forgedAgent).
		Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if verified > 0 {
		t.Errorf("%d unsigned row(s) were stored as VERIFIED — every downstream claim that rests on "+
			"attributability would then rest on nothing\n%s", verified, srv.Output())
	}
}

// TestAnEnrollmentTokenIsSingleUse — the property that makes a leaked token bounded rather than fatal.
func TestAnEnrollmentTokenIsSingleUse(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)

	token := issueToken(t, stack, "agent-once")
	first := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-once",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	pool := openPool(t, stack.DSN)
	Eventually(t, 90*time.Second, "the first agent to enrol", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM agent_identities WHERE agent_id='agent-once'`).Scan(&n)
		return n > 0
	})
	_ = first

	// The same token again, from a different identity. It must be refused: a token that can be replayed
	// turns one leaked string into unlimited fleet membership.
	second := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-twice",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	time.Sleep(3 * time.Second)

	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM agent_identities WHERE agent_id='agent-twice'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		t.Errorf("a REUSED enrollment token produced a second identity — one leaked string would then be "+
			"unlimited fleet membership\n%s", second.Output())
	}
}
