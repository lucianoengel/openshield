package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// CONSOLE-7: every health fact this platform knows lived on /metrics, behind a SEPARATE listener and a
// SEPARATE bearer token (PLAT-4b), so an operator session could not reach any of it. The console's first
// tile had no data source, and the question a fresh install actually raises — "is this empty because
// nothing happened, or because ingest is broken?" — had no answer at operator tier.

func healthVia(t *testing.T, s *controlplane.Server) controlplane.HealthReport {
	t.Helper()
	var got controlplane.HealthReport
	if err := json.Unmarshal([]byte(healthBody(t, s)), &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// healthBody drives the REAL route through the REAL tier gate, so this exercises what an operator
// reaches rather than the method behind it.
func healthBody(t *testing.T, s *controlplane.Server) string {
	t.Helper()
	ca := newOneCA(t)
	req := certReq(t, ca, http.MethodGet, "/health", "health-reader", "analyst")
	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(s, controlplane.RoleAnalyst, s.OperatorReadHandler()).
		ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health = %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	return rec.Body.String()
}

// TestHealthReportsTheFactsAnOperatorNeeds.
//
// Mutation: drop the `mux.HandleFunc("/health", …)` registration → 404 and this FAILS. Mutation: remove
// the mount from enroll_http.go → the route-closure guard fails instead, which is the other half.
func TestHealthReportsTheFactsAnOperatorNeeds(t *testing.T) {
	s := controlplane.New(requireDB(t))

	got := healthVia(t, s)
	if !got.DatabaseReachable {
		t.Fatalf("the database is reachable in this fixture and the report says otherwise: %+v", got)
	}
	// The schema numbers are REAL, not zero-valued: a report whose fields are all zero is indistinguishable
	// from one that could not gather anything, and that is the failure mode of every status page.
	if got.SchemaEmbedded == 0 || got.SchemaApplied == 0 {
		t.Errorf("schema counts are zero (embedded=%d applied=%d) — the report gathered nothing and said "+
			"nothing was wrong", got.SchemaEmbedded, got.SchemaApplied)
	}
	if got.SchemaSkew != 0 {
		t.Errorf("schema skew = %d against a migrated fixture", got.SchemaSkew)
	}
}

// TestAFollowerIsNotDegraded is the ticket's stated requirement: "specifies what the console shows when
// talking to a follower".
//
// Only the leader runs the scheduled loops, so a follower legitimately does none of them. Reporting that
// as a problem would mark every standby in a highly-available deployment as broken, which is how a team
// learns to ignore a health check.
//
// Mutation: add leadership to healthProblems → this FAILS.
func TestAFollowerIsNotDegraded(t *testing.T) {
	s := controlplane.New(requireDB(t))

	controlplane.SetLeaderHeld(false)
	t.Cleanup(func() { controlplane.SetLeaderHeld(false) })
	follower := healthVia(t, s)
	if follower.Leader {
		t.Fatal("leadership was not recorded as lost")
	}
	for _, p := range follower.Problems {
		if strings.Contains(strings.ToLower(p), "leader") {
			t.Errorf("a follower is reported as a problem: %q — a standby doing exactly what it should "+
				"must not read as broken", p)
		}
	}

	controlplane.SetLeaderHeld(true)
	if leader := healthVia(t, s); !leader.Leader {
		t.Error("leadership is held and the report does not say so — the field would then be one nobody " +
			"can act on")
	}
}

// TestDegradedNeverDisagreesWithItsOwnProblemList.
//
// `Degraded` is what colours the tile and `Problems` is what an operator reads. A boolean that can
// disagree with the list beside it is a boolean somebody will trust over the list.
//
// Mutation: set Degraded from anything other than len(Problems) → this FAILS.
func TestDegradedNeverDisagreesWithItsOwnProblemList(t *testing.T) {
	s := controlplane.New(requireDB(t))
	got := healthVia(t, s)
	if got.Degraded != (len(got.Problems) > 0) {
		t.Errorf("degraded=%v with %d problems: %v", got.Degraded, len(got.Problems), got.Problems)
	}
	// A problem must say what it COSTS, not just what it is. "broker disconnected" is already visible in
	// the fields; the list exists to say why an operator should stop what they are doing.
	for _, p := range got.Problems {
		if len(p) < 40 {
			t.Errorf("problem %q states a condition without its consequence — an operator reading this "+
				"list needs to know what it means, not what field it came from", p)
		}
	}
}

// TestAnUnanchoredLedgerIsReportedRatherThanAssumedFine.
//
// Forward integrity holds BETWEEN anchors (T-019/D64), so a ledger that has never been anchored can be
// silently truncated from the head. That is a real and common state — anchoring is optional — and a
// health report that stays silent about it lets a deployment believe it has a guarantee it does not.
//
// Mutation: drop the anchor branch from healthProblems → this FAILS.
func TestAnUnanchoredLedgerIsReportedRatherThanAssumedFine(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()

	var anchored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM anchors`).Scan(&anchored); err != nil {
		t.Fatal(err)
	}
	got := healthVia(t, s)
	var mentioned bool
	for _, p := range got.Problems {
		if strings.Contains(p, "anchor") {
			mentioned = true
		}
	}
	switch {
	case anchored == 0 && !mentioned:
		t.Errorf("no anchor exists and the report does not say so: %v — the deployment would believe it "+
			"has forward integrity it does not have", got.Problems)
	case anchored == 0 && got.LastAnchorAt != nil:
		t.Error("no anchor exists and the report carries a timestamp for one")
	case anchored > 0 && got.LastAnchorAt == nil:
		t.Error("an anchor exists and the report does not carry it")
	case anchored > 0 && mentioned:
		t.Errorf("an anchor exists and it is still reported as a problem: %v", got.Problems)
	}
}

// TestTheProblemListSerializesAsAnArrayEvenWhenEmpty. A console rendering `null` needs a nil check that
// is exactly the difference between "healthy" and "we could not tell", and the two must not look alike
// on the wire.
func TestTheProblemListSerializesAsAnArrayEvenWhenEmpty(t *testing.T) {
	s := controlplane.New(requireDB(t))
	if body := healthBody(t, s); strings.Contains(body, `"problems":null`) {
		t.Errorf("problems serialized as null: %s", body)
	}
}
