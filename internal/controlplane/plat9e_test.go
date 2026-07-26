package controlplane_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/lucianoengel/openshield/internal/controlplane"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// PLAT-9: fleet enforcement acknowledgement, carried by the heartbeat that already exists.
//
// D269 could PUBLISH a fleet-wide disable and could not tell whether it ARRIVED. "Did my disable reach
// the fleet?" is the question an operator asks thirty seconds after issuing one.

func heartbeat(t *testing.T, agent string, disabled bool, seq uint64) []byte {
	t.Helper()
	raw, err := proto.Marshal(&corev1.Heartbeat{
		AgentId: agent, Sequence: 1, ObservedAt: timestamppb.New(time.Now()),
		EnforcementDisabled: disabled, AppliedFleetSequence: seq,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestHeartbeatsAnswerWhetherTheFleetStoppedEnforcing.
//
// Mutation: do not project the heartbeat's enforcement fields → the fleet summary stays empty → FAILS.
func TestHeartbeatsAnswerWhetherTheFleetStoppedEnforcing(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// Three agents report: two have applied control 7 and stopped; one is still enforcing and behind.
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-a", true, 7))
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-b", true, 7))
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-c", false, 5))

	f, err := srv.FleetEnforcementState(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if f.Agents != 3 || f.Disabled != 2 || f.Enforcing != 1 {
		t.Errorf("fleet = %+v, want 3 agents / 2 disabled / 1 enforcing — an operator who issued a "+
			"disable cannot otherwise tell whether it arrived", f)
	}
	if f.NotCaughtUp != 1 {
		t.Errorf("not-caught-up = %d, want 1 (agent-c is at 5, target is 7)", f.NotCaughtUp)
	}

	// The LATEST report wins: an agent's CURRENT state is what is being asked about.
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-c", true, 7))
	f, err = srv.FleetEnforcementState(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if f.Disabled != 3 || f.Enforcing != 0 || f.NotCaughtUp != 0 {
		t.Errorf("after agent-c caught up: %+v, want all three disabled and caught up", f)
	}
	if n := countRows(t, pool, `SELECT count(*) FROM agent_enforcement`); n != 3 {
		t.Errorf("%d rows for 3 agents — a later heartbeat must UPDATE, not accumulate", n)
	}
}

// TestLocallyDisabledAgentIsVisible: the agent reports its ACTUAL state, so a host disabled by its LOCAL
// break-glass file shows up too — which the control plane has no other way to learn.
func TestLocallyDisabledAgentIsVisible(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	// Applied sequence 0 — this agent never received a fleet control. It is disabled locally.
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-local", true, 0))
	f, err := srv.FleetEnforcementState(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.Disabled != 1 {
		t.Errorf("a locally-disabled agent is invisible (%+v) — reporting only what we TOLD an agent "+
			"would miss the host someone stopped by hand", f)
	}
}

// TestFleetStateIsExposedOnMetrics closes an honesty gap I introduced: D270's proposal said "the summary
// and the metric are the operator surface", and only the summary existed — FleetEnforcementState had NO
// caller, which is the unwired-code failure this project's audits look for.
//
// Mutation: drop the fleet block from the metrics handler → FAILS.
func TestFleetStateIsExposedOnMetrics(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()

	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-m1", true, 3))
	srv.RecordHeartbeatForTest(ctx, heartbeat(t, "agent-m2", false, 1))

	rec := httptest.NewRecorder()
	srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("scrape returned %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"openshield_fleet_agents_reporting 2",
		"openshield_fleet_agents_disabled 1",
		"openshield_fleet_agents_enforcing 1",
		"openshield_fleet_agents_behind",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics do not expose %q — the summary function exists but nothing calls it, which "+
				"is a feature that reads as shipped and is not", want)
		}
	}
	// The gauge must carry its own caveat: a silent agent counts in none of these.
	if !strings.Contains(body, "absence is openshield_agents_overdue") {
		t.Error("the HELP text does not warn that a silent agent counts in none of these — a gauge " +
			"invites the reading that 0 enforcing means the fleet complied")
	}
}
