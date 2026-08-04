package controlplane

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// CONSOLE-7: THE CONSOLE CANNOT SEE WHETHER THE PROCESS IT IS TALKING TO IS WORKING.
//
// Every health fact this platform knows lives on `/metrics`, which sits on a SEPARATE listener behind a
// SEPARATE constant-time bearer token (PLAT-4b). An operator session cannot reach it, so the console's
// first tile has no data source at all — and the one question a fresh install raises is precisely the one
// it cannot answer: an empty incident queue looks identical to broken ingest.
//
// # WHY THIS IS A REPORT AND NOT A LIVENESS PROBE
//
// It always answers 200 with the facts, and the caller decides. Two reasons, and the first is the whole
// ticket:
//
// A FOLLOWER IS HEALTHY. Only the leader runs the scheduled loops (PLAT-2b), so a follower legitimately
// holds no leadership and is doing exactly what it should. Collapsing that into a status code makes every
// follower in a highly-available deployment look broken, which is how a team learns to ignore the check.
//
// AND A SINGLE CODE CANNOT SAY WHAT IS WRONG. "Degraded" is not actionable; "the durable telemetry
// consumer has been rebuilt 4 times and failed twice, so your broker is losing its state" is. Each
// problem below names the fact, what it means, and what to do — the D31 rule that a gap must never be
// silent, applied to the surface an operator actually reads.
//
// A load balancer wanting a liveness probe should use TCP reachability of this port; this endpoint is for
// the human, and mixing the two audiences is how a probe ends up gating traffic on "is this the leader".

// leaderHeld is whether THIS process currently holds leadership.
//
// A package-level atomic rather than a Server field because leadership is a property of the PROCESS, not
// of a Server value: `internal/controlplane.Leader` elects, `cmd/openshield-server` acts on it, and the
// Server that serves this route is a third object none of them holds a reference to. Threading one
// through would mean the health surface only works if somebody remembered to wire it — the exact defect
// class this ticket exists inside.
var leaderHeld atomic.Bool

// SetLeaderHeld records whether this process holds leadership. Called by whoever runs the election.
func SetLeaderHeld(held bool) { leaderHeld.Store(held) }

// HealthReport is what an operator sees about the process answering them.
type HealthReport struct {
	// Leader is whether this process runs the scheduled work. FALSE IS NOT AN ERROR.
	Leader bool `json:"leader"`
	// BrokerConnected is the live NATS connection state. False with JetStream in use means telemetry is
	// not arriving here, whatever the incident queue looks like.
	BrokerConnected bool `json:"broker_connected"`
	// BrokerConfigured is false when this deployment runs without a broker at all, so an absent
	// connection is distinguishable from a broken one.
	BrokerConfigured bool `json:"broker_configured"`
	// IngestRepairs / IngestRepairFailures are PLAT-10's self-healing counters. Repairs > 0 means the
	// broker lost its stream and this process rebuilt it — recovered, but evidence worth seeing.
	IngestRepairs        int64 `json:"ingest_repairs"`
	IngestRepairFailures int64 `json:"ingest_repair_failures"`
	// DatabaseReachable is a real round trip, not a cached flag: a pool that has not been used lately
	// reports healthy right up until the first query fails.
	DatabaseReachable bool `json:"database_reachable"`
	// SchemaEmbedded / SchemaApplied / SchemaSkew are PLAT-9. Skew > 0 means the DATABASE is ahead of
	// this binary — a rollback left this process reading a schema it does not know.
	SchemaEmbedded int `json:"schema_embedded"`
	SchemaApplied  int `json:"schema_applied"`
	SchemaSkew     int `json:"schema_skew"`
	// LastAnchorAt / LastAnchorSequence describe the newest witnessed ledger checkpoint (T-019/D64).
	// ZERO MEANS NEVER ANCHORED, which is a real and common state — anchoring is optional — and the
	// problem list says what it costs rather than the field pretending to a number.
	LastAnchorAt       *time.Time `json:"last_anchor_at,omitempty"`
	LastAnchorSequence *int64     `json:"last_anchor_sequence,omitempty"`

	// Degraded is a convenience for the tile colour, derived from Problems and never set independently —
	// a boolean that can disagree with the list beside it is a boolean somebody will trust over the list.
	Degraded bool `json:"degraded"`
	// Problems names each thing that is wrong, in the operator's terms, with what to do. Empty is the
	// healthy case and is serialized as [] rather than null, so a console can render it without a nil
	// check that would otherwise be the difference between "healthy" and "we could not tell".
	Problems []string `json:"problems"`
}

// Health builds the report. Every fact is read at call time; nothing here is cached, because a health
// surface that serves a cached answer reports the moment it was last convenient rather than now.
func (s *Server) Health(ctx context.Context) HealthReport {
	s.mu.Lock()
	conn := s.conn
	pool := s.pool
	s.mu.Unlock()

	r := HealthReport{
		Leader:               leaderHeld.Load(),
		BrokerConfigured:     conn != nil,
		BrokerConnected:      conn != nil && conn.IsConnected(),
		IngestRepairs:        s.ingest.repairs.Load(),
		IngestRepairFailures: s.ingest.failed.Load(),
		Problems:             []string{},
	}

	if pool != nil {
		// A BOUNDED round trip. An unreachable database must make this endpoint answer "unreachable"
		// promptly, not hang for as long as the driver's own timeout — a health report that stops
		// responding when things break is a health report that is absent exactly when it is needed.
		pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		r.DatabaseReachable = pool.Ping(pctx) == nil
		cancel()

		if r.DatabaseReachable {
			if embedded, applied, err := postgres.SchemaSkew(ctx, pool); err == nil {
				r.SchemaEmbedded, r.SchemaApplied = embedded, applied
				if applied > embedded {
					r.SchemaSkew = applied - embedded
				}
			}
			var seq int64
			var at time.Time
			if err := pool.QueryRow(ctx,
				`SELECT sequence, anchored_at FROM anchors ORDER BY anchored_at DESC LIMIT 1`).
				Scan(&seq, &at); err == nil {
				r.LastAnchorSequence, r.LastAnchorAt = &seq, &at
			}
		}
	}

	r.Problems = healthProblems(r)
	r.Degraded = len(r.Problems) > 0
	return r
}

// healthProblems turns the facts into what an operator should do about them.
//
// EACH ENTRY NAMES THE CONSEQUENCE, not just the state. "broker disconnected" is a fact an operator can
// read off the field above; "telemetry is not arriving, and every agent is spooling toward its queue
// limit where it will begin dropping the OLDEST records" is why they should stop what they are doing.
//
// Leadership is deliberately absent: a follower is not a problem, and listing it as one would train
// people to ignore this list on the majority of their processes.
func healthProblems(r HealthReport) []string {
	out := []string{}
	if !r.DatabaseReachable {
		out = append(out, "the database is not reachable from this process — nothing is being persisted "+
			"or served, and an empty incident queue right now means nothing")
	}
	if r.BrokerConfigured && !r.BrokerConnected {
		out = append(out, "the message broker is not connected — endpoint telemetry is not arriving here, "+
			"and every agent is spooling toward its queue limit, where it begins dropping the OLDEST "+
			"records (D40/D67)")
	}
	if r.SchemaSkew > 0 {
		out = append(out, "the database has applied more migrations than this binary embeds "+
			"(PLAT-9): a rollback left this process reading a schema ahead of it, so some columns it "+
			"writes may not be the ones the newer code reads")
	}
	if r.IngestRepairFailures > 0 {
		out = append(out, "the durable telemetry consumer could not be rebuilt — ingest is DOWN and this "+
			"process cannot repair it (PLAT-10); check that JetStream is enabled on the broker")
	} else if r.IngestRepairs > 0 {
		// RECOVERED IS STILL WORTH SAYING. A system that heals silently teaches nobody that its broker
		// is being replaced under it, and the next failure looks like the first.
		out = append(out, "the durable telemetry consumer has been rebuilt — this process recovered, but "+
			"the broker lost its stream, and records published into the gap were REFUSED rather than "+
			"buffered (PLAT-10)")
	}
	if r.LastAnchorAt == nil {
		out = append(out, "the audit ledger has never been externally anchored — forward integrity holds "+
			"BETWEEN anchors, so with none, history can be silently TRUNCATED from the head (T-019/D64)")
	}
	return out
}

// healthHandler serves GET /health at the analyst tier — the lowest, because every operator using the
// console needs to know whether the answers it is giving them can be trusted.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.Health(r.Context()))
}
