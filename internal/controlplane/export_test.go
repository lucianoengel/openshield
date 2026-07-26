package controlplane

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/notify"
)

// NewLeaderForTest builds a Leader with a fast poll interval so the election/failover test runs
// quickly (PLAT-2b).
func NewLeaderForTest(pool *pgxpool.Pool, poll time.Duration) *Leader {
	return &Leader{pool: pool, key: leaderLockKey, poll: poll}
}

// LeaderLockKey exposes the advisory-lock key so a failover test can find and terminate the backend
// that HOLDS leadership (R34-6, test proposal #7).
func LeaderLockKey() int64 { return leaderLockKey }

// RequireRoleForTest exposes the unexported role gate to the external test
// package, wrapping a handler that writes 200 on success — so a test can assert
// the 401/403/200 outcomes directly.
func RequireRoleForTest(role string) http.Handler {
	return requireRole(role, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// RequireTierForTest exposes the tiered RBAC gate (PLAT-3) so a test can assert the
// 401/403/200 outcomes of a minimum-tier requirement directly.
func RequireTierForTest(minRole string) http.Handler {
	return requireTier(minRole, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// EmitForTest exposes the unexported emit so a test can prove an unconfigured server
// never fills its notify queue (R34-9).
func (s *Server) EmitForTest(n notify.Notification) { s.emit(context.Background(), n) }

// ScanCloudTrailDirForTest runs one CloudTrail directory scan (SIEM-4), so a test can drive ingest
// deterministically without waiting on the poller's ticker.
func (s *Server) ScanCloudTrailDirForTest(dir string) { s.scanCloudTrailDir(context.Background(), dir) }

// ScanWEFDirForTest runs one WEF directory scan (SIEM-4), for deterministic ingest tests.
func (s *Server) ScanWEFDirForTest(dir string) { s.scanWEFDir(context.Background(), dir) }

// BackoffFor / NakBackoffBase / NakBackoffMax expose the pure Nak redelivery schedule (R34-4)
// so a test can assert the doubling-and-cap behavior without a live JetStream message.
func BackoffFor(numDelivered uint64) time.Duration { return backoffFor(numDelivered) }
func NakBackoffBase() time.Duration                { return nakBackoffBase }
func NakBackoffMax() time.Duration                 { return nakBackoffMax }

// UnifiedDomainFor / AlertableAction / SeverityForDecision / AlertTitleFor expose the pure
// decision→alert mappings (XDR-2) so a test can assert them exhaustively over the closed Action and
// EventKind enums without driving a full ingest.
func UnifiedDomainFor(kind corev1.EventKind) (string, bool) { return unifiedDomainFor(kind) }
func AlertableAction(a corev1.Action) bool                  { return alertableAction(a) }
func SeverityForDecision(a corev1.Action, confidence float64) string {
	return severityForDecision(a, confidence)
}
func AlertTitleFor(a corev1.Action, kind corev1.EventKind) string { return alertTitleFor(a, kind) }

// MatchesSequence / EscalateSeverity / MaxSeverity / DistinctInOrder expose the pure cross-domain rule
// logic (XDR-4) so the ordering and escalation semantics — the subtle part of the rule — are testable
// exhaustively without a database.
func MatchesSequence(ordered, want []string) bool { return matchesSequence(ordered, want) }
func EscalateSeverity(base string, domainCount int) string {
	return escalateSeverity(base, domainCount)
}
func MaxSeverity(severities []string) string   { return maxSeverity(severities) }
func DistinctInOrder(values []string) []string { return distinctInOrder(values) }

// PlaybookStepRegistry exposes the CLOSED step registry's key set (SOAR-4), so a test can assert both
// that it equals the declared vocabulary and that it contains exactly the seven Tier-1 (non-actuating)
// steps — an actuating addition then cannot land without changing an assertion that says so.
func PlaybookStepRegistry() []string {
	out := make([]string, 0, len(playbookSteps))
	for k := range playbookSteps {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return out
}

// DeclaredPlaybookSteps is the vocabulary as DECLARED (the StepName constants), listed independently of
// the registry so the two sets can be compared in both directions.
func DeclaredPlaybookSteps() []string {
	out := []string{
		string(StepEnrich), string(StepNotify), string(StepOpenCase), string(StepPlaceHold),
		string(StepTag), string(StepAnnotate), string(StepWaitForApproval),
	}
	sort.Strings(out)
	return out
}

// RecordHeartbeatForTest exposes heartbeat ingestion so a test can drive the PLAT-9 enforcement
// acknowledgement through the REAL path rather than inserting the projection directly.
func (s *Server) RecordHeartbeatForTest(ctx context.Context, data []byte) {
	s.recordHeartbeat(ctx, data)
}

// InsertFleetTelemetryForTest seeds one aggregate row, so a detector test can drive the REAL read path
// (verified-only, proto-decoded) rather than a hand-built in-memory fixture.
func (s *Server) InsertFleetTelemetryForTest(t interface{ Fatalf(string, ...any) },
	agentID, eventID string, payload []byte, verified bool) {
	if _, err := s.pool.Exec(context.Background(),
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified) VALUES ($1,'event',$2,$3,$4)`,
		agentID, eventID, payload, verified); err != nil {
		t.Fatalf("seeding fleet telemetry: %v", err)
	}
}
