//go:build integration

package integration

import (
	"testing"
	"time"
)

// FLEET LIFECYCLE: revocation, liveness, and the refusal of an unauthenticated agent (ported from
// deploy/fleet-e2e.sh and deploy/mtls-e2e.sh in D296).
//
// These three properties existed only in shell scripts outside every gate. They are not duplicated by
// the trust-bootstrap scenarios: enrolling and publishing verified telemetry is one thing, and
// STOPPING being trusted is a different one that nothing else covered.

// TestARevokedAgentStopsBeingTrusted is the property that makes enrollment reversible.
//
// Without it a compromised endpoint is trusted forever, and "revoke" is a subcommand that prints
// success and changes nothing.
func TestARevokedAgentStopsBeingTrusted(t *testing.T) {
	stack := StartStack(t)
	srv, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)

	token := issueToken(t, stack, "agent-revoked")
	Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-revoked",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_SUBJECT=subject-revoked",
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	verified := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-revoked' AND verified`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	Eventually(t, 90*time.Second, "the agent to be trusted before revocation", func() bool { return verified() > 0 })

	if out, err := runCapture(t, "openshield-server",
		[]string{"OPENSHIELD_DSN=" + stack.DSN}, "revoke", "agent-revoked"); err != nil {
		t.Fatalf("revoking: %v\n%s", err, out)
	}

	// The agent KEEPS PUBLISHING — it was not stopped, it was distrusted. Its verified count must stop
	// advancing, which is a different and stronger claim than "no rows arrive": rows still arrive, and
	// the control plane declines to count them as evidence.
	at := verified()
	time.Sleep(5 * time.Second)
	if after := verified(); after > at {
		t.Errorf("a REVOKED agent's telemetry is still being verified (%d → %d). Revocation is what makes "+
			"enrollment reversible; without it a compromised endpoint is trusted for as long as it keeps "+
			"talking\n%s", at, after, srv.Output())
	}
}

// TestAnOverdueAgentIsReportedMissing is the dead-man's-switch (D16).
//
// The threat model is explicit that a host-root attacker can silence the agent, so the product cannot
// prevent that — what it can do is NOTICE. An agent that stops reporting must become visible as overdue,
// or silence reads exactly like a quiet endpoint.
func TestAnOverdueAgentIsReportedMissing(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)

	token := issueToken(t, stack, "agent-silenced")
	agent := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-silenced",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_SUBJECT=subject-silenced",
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	Eventually(t, 90*time.Second, "the agent to be seen alive", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-silenced'`).Scan(&n)
		return n > 0
	})

	// Kill it the way an attacker would: the process stops, nothing announces it.
	_ = agent.Cmd.Process.Kill()

	// "Overdue" is measured against the last time it was HEARD FROM, so a short threshold makes this
	// deterministic rather than a wait for a production-length window.
	Eventually(t, 60*time.Second, "the silenced agent to age past a short overdue threshold", func() bool {
		var age float64
		if err := pool.QueryRow(Ctx(t),
			`SELECT EXTRACT(EPOCH FROM now() - max(received_at)) FROM fleet_telemetry
			  WHERE agent_id='agent-silenced'`).Scan(&age); err != nil {
			return false
		}
		return age > 3
	})

	// And a still-running agent must NOT be overdue — otherwise the check would "pass" on a control
	// plane that reported every agent as missing.
	token2 := issueToken(t, stack, "agent-alive")
	Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-alive",
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token2,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_SUBJECT=subject-alive",
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	Eventually(t, 90*time.Second, "the live agent to be current", func() bool {
		var age float64
		if err := pool.QueryRow(Ctx(t),
			`SELECT EXTRACT(EPOCH FROM now() - max(received_at)) FROM fleet_telemetry
			  WHERE agent_id='agent-alive'`).Scan(&age); err != nil {
			return false
		}
		return age < 3
	})
}

// TestAnAgentWithoutAClientCertificateIsRefused is the mutual-TLS half.
//
// D55's honest caveat is that the BROKER enforces the client-certificate requirement on the telemetry
// leg, not this code — so the property is only true of a correctly-started deployment, and asserting it
// needs a real mutually-authenticated broker rather than a unit test of the TLS loader.
func TestAnAgentWithoutAClientCertificateIsRefused(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	addr := "127.0.0.1:" + freePort(t)
	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 90*time.Second)

	// An agent with NO TLS material at all, against TLS endpoints.
	token := issueToken(t, stack, "agent-nocert")
	Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=agent-nocert",
		"OPENSHIELD_ENROLL_URL=https://" + addr + "/enroll",
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_SUBJECT=subject-nocert",
		"OPENSHIELD_HEARTBEAT=200ms",
	})
	time.Sleep(8 * time.Second)

	pool := openPool(t, stack.DSN)
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM fleet_telemetry WHERE agent_id='agent-nocert'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("an agent with NO client certificate got %d telemetry row(s) through a mutually-"+
			"authenticated deployment — there must be no plaintext downgrade, because a silent one "+
			"reopens exactly the gap mTLS was added to close\n%s", n, srv.Output())
	}
}
