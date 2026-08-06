//go:build integration

package integration

import (
	"path/filepath"
	"testing"
	"time"
)

// THE REAL ENDPOINT AGENT'S LIVENESS (CONSOLE-8 increment 2).
//
// Before this, the ONLY heartbeat producer in the entire tree was `cmd/openshield-fleet-agent` — the
// fleet SIMULATOR, whose own doc comment says it "does NOT classify files or run the pipeline (that is
// the engine)". Two shipped features therefore described nothing on any real deployment:
//
//   - PLAT-9's enforcement acknowledgement, because `agent_enforcement` is written only from a heartbeat.
//     "Did my fleet disable arrive?" read an empty table on every deployment running engines.
//   - The dead-man's-switch (T-018/D16), because last-seen advances from verified telemetry and an IDLE
//     endpoint produces none — so a healthy quiet machine looked exactly like a killed one.
//
// That cannot be proven by a package test: the projection is happy to store whatever it is handed, and
// what was missing was a PRODUCER. So this runs the real engine and asks the database.

func TestTheRealEngineReportsItselfAliveWithoutProducingTelemetry(t *testing.T) {
	stack := StartStack(t)
	_, enrollURL := startServer(t, stack)
	pool := openPool(t, stack.DSN)
	work := t.TempDir()

	const agentID = "engine-heartbeat-1"
	token := issueToken(t, stack, agentID)

	// A WATCH DIRECTORY THAT STAYS EMPTY, and that is the point of the scenario. This endpoint produces
	// no events at all — exactly the idle host that used to be indistinguishable from a dead one.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_HEARTBEAT_INTERVAL=500ms",
	})
	eng.WaitForOutput("heartbeat ACTIVE", 90*time.Second)

	// THE ASSERTION: a row exists in the table PLAT-9 reads, for an agent that has emitted no detections.
	Eventually(t, 90*time.Second, "the engine's enforcement acknowledgement to reach the control plane",
		func() bool {
			var n int
			_ = pool.QueryRow(Ctx(t),
				`SELECT count(*) FROM agent_enforcement WHERE agent_id = $1`, agentID).Scan(&n)
			return n > 0
		})

	var platform, version *string
	var spool *int64
	var disabled bool
	if err := pool.QueryRow(Ctx(t),
		`SELECT disabled, platform, agent_version, spool_depth FROM agent_enforcement WHERE agent_id = $1`,
		agentID).Scan(&disabled, &platform, &version, &spool); err != nil {
		t.Fatalf("reading the engine's self-report: %v\n%s", err, eng.Output())
	}

	// INVENTORY, and it must be REPORTED rather than defaulted. A NULL here means the engine sent a
	// heartbeat carrying none of these — which is what an agent built before this increment sends, and
	// would mean the new fields are not on the wire.
	if platform == nil || *platform == "" {
		t.Errorf("the engine reported no platform: the heartbeat reached the control plane without the "+
			"inventory fields\n%s", eng.Output())
	}
	if version == nil || *version == "" {
		t.Errorf("the engine reported no version. `scripts/release.sh` stamped `-X main.version` at a "+
			"symbol no command declared, and the linker ignores an unknown -X target in SILENCE — so "+
			"every shipped binary carried no version at all\n%s", eng.Output())
	}
	// An unstamped local build must be IDENTIFIABLE as one, not empty: "we could not tell" and "this
	// host runs something nobody released" are different facts.
	if version != nil && *version != "dev" {
		t.Logf("agent_version = %q (a stamped build)", *version)
	}
	if spool == nil {
		t.Errorf("the engine reported no spool depth — a depth that keeps climbing is an outage the " +
			"agent is surviving and nobody has noticed")
	}
	if disabled {
		t.Errorf("the engine reports enforcement DISABLED with no break-glass file and no fleet " +
			"control — the switch fails toward ENFORCING, so this is either a wrong report or a real " +
			"and much worse problem")
	}

	// AND THE DEAD-MAN'S-SWITCH NOW SEES IT. The heartbeat is stored as a telemetry row so last-seen
	// advances for an agent that has detected nothing, which is the entire T-018/D16 claim.
	Eventually(t, 60*time.Second, "last-seen to advance from the heartbeat alone", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1 AND verified = true`,
			agentID).Scan(&n)
		return n > 0
	})
}
