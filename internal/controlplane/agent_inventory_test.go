package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/agent/identity"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// CONSOLE-8 increment 2: the roster describes what is running, and an agent that cannot say is reported
// as not having said.
//
// The heartbeat is the only channel these facts have, and until this increment the only producer of a
// heartbeat in the whole tree was the fleet SIMULATOR — so PLAT-9's enforcement acknowledgement and the
// dead-man's-switch both described nothing on a deployment running real engines. The integration test is
// what proves the engine now sends one; these prove the projection is honest about what it receives.

func inventoryHeartbeat(t *testing.T, agent, platform, version string, spool uint64) []byte {
	t.Helper()
	raw, err := proto.Marshal(&corev1.Heartbeat{
		AgentId: agent, Sequence: 1, ObservedAt: timestamppb.New(time.Now()),
		Platform: platform, AgentVersion: version, SpoolDepth: spool,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rosterFor(t *testing.T, srv *controlplane.Server, agent string) controlplane.FleetAgent {
	t.Helper()
	roster, err := srv.Fleet(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range roster.Agents {
		if a.AgentID == agent {
			return a
		}
	}
	t.Fatalf("%s is not on the roster: %+v", agent, roster.Agents)
	return controlplane.FleetAgent{}
}

// TestAnAgentThatReportsItsBuildIsDescribedOnTheRoster.
//
// Mutation: drop platform/agent_version/spool_depth from the upsert → FAILS.
// Mutation: drop them from the roster SELECT → FAILS.
func TestAnAgentThatReportsItsBuildIsDescribedOnTheRoster(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	execSQL(t, pool, `DELETE FROM agent_enforcement`)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	execSQL(t, pool, `DELETE FROM agent_identities`)
	execSQL(t, pool, `INSERT INTO agent_identities (agent_id, public_key) VALUES ('described', '\x00')`)

	srv.RecordHeartbeatForTest(ctx, inventoryHeartbeat(t, "described", "linux/amd64", "v1.4.0", 17))

	a := rosterFor(t, srv, "described")
	if a.Platform == nil || *a.Platform != "linux/amd64" {
		t.Errorf("platform = %v, want linux/amd64", a.Platform)
	}
	if a.AgentVersion == nil || *a.AgentVersion != "v1.4.0" {
		t.Errorf("agent_version = %v, want v1.4.0 — \"which hosts are not on the current release?\" is "+
			"the question a fleet inventory exists to answer", a.AgentVersion)
	}
	if a.SpoolDepth == nil || *a.SpoolDepth != 17 {
		t.Errorf("spool_depth = %v, want 17 — a depth that keeps climbing is an outage the agent is "+
			"surviving and nobody has noticed", a.SpoolDepth)
	}
}

// TestAnOlderAgentIsReportedAsNotHavingSaidRatherThanAsHealthy.
//
// This is the whole honesty argument for the nullable columns. proto3 gives an absent string "" and an
// absent number 0, and both are CLAIMS: "" reads as a version we could not determine, and a spool depth
// of 0 reads as a comfortably empty queue on a host that might be spooling hard.
//
// Mutation: store h.GetPlatform() / h.GetSpoolDepth() directly instead of nil-ing the zero values → FAILS.
func TestAnOlderAgentIsReportedAsNotHavingSaidRatherThanAsHealthy(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	execSQL(t, pool, `DELETE FROM agent_enforcement`)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	execSQL(t, pool, `DELETE FROM agent_identities`)
	execSQL(t, pool, `INSERT INTO agent_identities (agent_id, public_key) VALUES ('old-build', '\x00')`)

	// The heartbeat an agent built before this increment sends: identity and liveness, nothing else.
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "old-build", false, 3))

	a := rosterFor(t, srv, "old-build")
	if a.Platform != nil {
		t.Errorf("platform = %q for an agent that reported none", *a.Platform)
	}
	if a.AgentVersion != nil {
		t.Errorf("agent_version = %q for an agent that reported none — an empty string reads as a "+
			"version we could not determine, which is a different and worse claim", *a.AgentVersion)
	}
	if a.SpoolDepth != nil {
		t.Errorf("spool_depth = %d for an agent that reported none — zero reads as an empty queue, and "+
			"this host may be spooling hard", *a.SpoolDepth)
	}
	// The facts it DID report are still there, or the assertions above would hold for a heartbeat that
	// was never projected at all.
	if a.EnforcementDisabled == nil || a.AppliedSequence == nil || *a.AppliedSequence != 3 {
		t.Fatalf("the older agent's enforcement report did not land (%+v) — the negative assertions "+
			"above would then prove nothing", a)
	}
}

// TestTheLatestReportWinsForInventoryToo — an agent that upgrades must not keep advertising its old
// version, and the roster answers about NOW.
func TestTheLatestReportWinsForInventoryToo(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	execSQL(t, pool, `DELETE FROM agent_enforcement`)
	execSQL(t, pool, `DELETE FROM fleet_telemetry`)
	execSQL(t, pool, `DELETE FROM agent_identities`)
	execSQL(t, pool, `INSERT INTO agent_identities (agent_id, public_key) VALUES ('upgraded', '\x00')`)

	srv.RecordHeartbeatForTest(ctx, inventoryHeartbeat(t, "upgraded", "linux/amd64", "v1.3.0", 0))
	srv.RecordHeartbeatForTest(ctx, inventoryHeartbeat(t, "upgraded", "linux/amd64", "v1.4.0", 0))

	if a := rosterFor(t, srv, "upgraded"); a.AgentVersion == nil || *a.AgentVersion != "v1.4.0" {
		t.Errorf("agent_version = %v after an upgrade, want v1.4.0", a.AgentVersion)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM agent_enforcement`); n != 1 {
		t.Errorf("%d rows for one agent — a later heartbeat must UPDATE, not accumulate", n)
	}
}

// TestASIGNEDHeartbeatProjectsTheEnforcementAcknowledgement.
//
// THE HALF THAT WAS INVISIBLE. `recordEnforcementState` was reached only from `recordHeartbeat`, which
// is subscribed on the PLAINTEXT heartbeat subject — and nothing in the tree publishes there. Every
// producer signs, so the signed path saw every heartbeat, stored it as telemetry, and dropped the
// enforcement fields. `agent_enforcement` was written by nothing but tests, and PLAT-9's "did my fleet
// disable arrive?" read an empty table on every deployment that has ever run.
//
// Both halves passed their own tests throughout: the projection stored what it was handed, and the
// producer sent what it was asked to. Only driving the REAL subject shows it.
//
// Mutation: remove the heartbeat branch from handleSigned → FAILS.
// Mutation: project it for UNVERIFIED envelopes too → the second half of this test FAILS.
func TestASIGNEDHeartbeatProjectsTheEnforcementAcknowledgement(t *testing.T) {
	url := embeddedNATS(t)
	srv := runServer(t, url)
	conn, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	execSQL(t, mustPoolCP(t), `DELETE FROM agent_enforcement`)

	pub := signedAgent(t, srv, conn, "agent-hb-signed")
	if err := pub.PublishHeartbeat(context.Background(), &corev1.Heartbeat{
		AgentId: "agent-hb-signed", ObservedAt: timestamppb.Now(),
		EnforcementDisabled: true, AppliedFleetSequence: 9,
		Platform: "linux/arm64", AgentVersion: "v2.0.0", SpoolDepth: 4,
	}); err != nil {
		t.Fatal(err)
	}

	pool := mustPoolCP(t)
	waitFor(t, func() bool {
		return countRows(t, pool, `SELECT count(*) FROM agent_enforcement WHERE agent_id='agent-hb-signed'`) == 1
	})
	var disabled bool
	var applied int64
	var platform, version *string
	if err := pool.QueryRow(context.Background(),
		`SELECT disabled, applied_sequence, platform, agent_version FROM agent_enforcement
		  WHERE agent_id='agent-hb-signed'`).Scan(&disabled, &applied, &platform, &version); err != nil {
		t.Fatal(err)
	}
	if !disabled || applied != 9 {
		t.Errorf("disabled=%v applied=%d — the signed heartbeat's enforcement acknowledgement did not "+
			"land, which is the whole of PLAT-9", disabled, applied)
	}
	if platform == nil || version == nil {
		t.Errorf("inventory did not survive the signed path: platform=%v version=%v", platform, version)
	}

	// AND AN UNVERIFIED ENVELOPE CANNOT MOVE IT (D44/D50). Otherwise any publisher could tell the
	// control plane that a live endpoint has already stopped enforcing, and hide it behind a forged
	// acknowledgement.
	forged, _ := identity.Generate("agent-hb-signed")
	payload, _ := proto.Marshal(&corev1.Heartbeat{
		AgentId: "agent-hb-signed", ObservedAt: timestamppb.Now(), EnforcementDisabled: false,
		AppliedFleetSequence: 999,
	})
	b, _ := proto.Marshal(&corev1.SignedTelemetry{AgentId: "agent-hb-signed", Sequence: 500,
		Kind: "heartbeat", Payload: payload, Signature: forged.Sign(500, payload)})
	_ = conn.Publish(natsx.SubjectSigned, b)

	waitFor(t, func() bool { return srv.RejectedTelemetry.Load() > 0 })
	if err := pool.QueryRow(context.Background(),
		`SELECT disabled, applied_sequence FROM agent_enforcement WHERE agent_id='agent-hb-signed'`).
		Scan(&disabled, &applied); err != nil {
		t.Fatal(err)
	}
	if !disabled || applied != 9 {
		t.Errorf("an UNVERIFIABLE heartbeat moved the acknowledgement to disabled=%v applied=%d — a "+
			"forged 'already disabled' would hide a live endpoint from the operator who is trying to "+
			"stop it", disabled, applied)
	}
}
