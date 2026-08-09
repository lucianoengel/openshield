package controlplane

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
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

// RequireTierForTest exposes the tiered RBAC gate (PLAT-3/ZT-7) so a test can assert the
// 401/403/200 outcomes of a minimum-tier requirement directly.
//
// It takes a Server now because the gate resolves the role SERVER-SIDE rather than from the certificate
// (ZT-7). A zero Server has no pool, so the lookup misses and the legacy certificate fallback applies —
// which is what the existing PLAT-3 cases assert, unchanged.
func RequireTierForTest(s *Server, minRole string) http.Handler {
	return s.requireTier(minRole, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

// PlausibleObservationTimeForTest exposes the clock-skew decision so a test can assert it directly.
//
// DIRECTLY, because the end-to-end version does not work and the reason is instructive: seeding beaconing
// flows inserts them in a tight loop, so their RECEIPT times are milliseconds apart and carry no rhythm for
// the fallback to find. A test asserting "a future-dated beacon is still detected" therefore cannot pass
// on the fallback — and the first version of it passed anyway, on rows a previous test had left behind.
// Clearing the table before seeding is what exposed that.
func PlausibleObservationTimeForTest(ev *corev1.Event, receivedAt time.Time, tolerance time.Duration) (time.Time, bool) {
	return plausibleObservationTime(ev, receivedAt, tolerance)
}

// RequireTierForTestHandler wraps a real handler in the tier gate, so a test exercises the request
// exactly as production builds it — including the authenticated principal the gate puts on the context
// (CONSOLE-1). RequireTierForTest answers only the gate's own status code; this one lets the handler run.
func RequireTierForTestHandler(s *Server, minRole string, h http.Handler) http.Handler {
	return s.requireTier(minRole, h)
}

// RequirePrivacyOfficerForTestHandler wraps a real handler in the DATA-SUBJECT gate (CONSOLE-1), which
// no operator tier satisfies. Exported separately from the tier gate for the same reason the production
// wrapper is: routing a privacy route through a function whose name says "tier" is how the two would
// quietly become one again.
func RequirePrivacyOfficerForTestHandler(s *Server, h http.Handler) http.Handler {
	return s.requirePrivacyOfficer(h)
}

// RecordFleetControlForTest exposes the break-glass register's writer, so a CONSOLE-8 derivation test can
// seed controls at chosen sequences and expiries without standing up a broker, a signer and a four-eyes
// approval for each one. The record-on-publish test drives the REAL path; these seed the thing that path
// writes, which is what the derivation is a function of.
func (s *Server) RecordFleetControlForTest(t interface{ Fatalf(string, ...any) }, id string,
	verb corev1.FleetVerb, seq uint64, issued, expires time.Time, reason string) {
	if err := s.recordFleetControl(context.Background(), id, verb, seq, issued, expires, reason); err != nil {
		t.Fatalf("recording fleet control %s: %v", id, err)
	}
}

// ViewAuditedForTest wraps a handler in the CONSOLE-5 view audit, so a test can assert the two things
// that matter about it — that the record exists BEFORE the wrapped handler runs, and that the handler
// does not run at all when the record fails. Asserting on a row after the response would pass equally
// against a wrapper that recorded afterwards, which is the ordering the whole invariant is about.
func ViewAuditedForTest(s *Server, h http.Handler) http.Handler { return s.viewAudited(h) }

// ViewAuditedAsForTest mounts the view audit behind a stub that attaches an already-authenticated
// certificate principal, standing in for the tier gate.
//
// It exists for ONE case and the reason is worth stating: proving that a read whose record fails is not
// served requires a database that refuses writes, and the real tier gate resolves the operator's grant
// against that same database. Driven through the gate, a dead pool is refused by the gate and the
// handler never runs — so the assertion "the handler did not run" would pass without the recording
// layer doing anything at all. That is a vacuous test, and this removes the gate from the path so the
// refusal under test is the one the audit makes.
func ViewAuditedAsForTest(s *Server, cn string, h http.Handler) http.Handler {
	p, err := certPrincipal(cn)
	if err != nil {
		panic("ViewAuditedAsForTest: " + err.Error())
	}
	audited := s.viewAudited(h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		audited.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// ViewAuditExemptForTest and ViewAuditedInHandlerForTest expose the two route-decision tables. They are
// separate maps on purpose — "audited by its own handler" and "deliberately not audited" are different
// claims, and a test asserts they stay disjoint, because collapsing them is how a stated residual would
// silently become an exemption nobody wrote down.
func ViewAuditExemptForTest() map[string]string      { return viewAuditExempt }
func ViewAuditedInHandlerForTest() map[string]string { return viewAuditedInHandler }

// CanonicalViewQueryForTest exposes the recorded-query rendering: sorted parameters, bounded length,
// truncation marked in the value.
func CanonicalViewQueryForTest(v url.Values) string { return canonicalViewQuery(v) }

// MaxViewQueryLenForTest is the bound, so the truncation test derives its input from the code rather
// than from a number copied into the test that would stop meaning anything if the bound moved.
func MaxViewQueryLenForTest() int { return maxViewQueryLen }

// ViewQueryTruncatedForTest is the marker appended to a query that did not fit.
func ViewQueryTruncatedForTest() string { return viewQueryTruncated }

// DecodeCursorForTest exposes the decoded cursor so a test can assert what it does NOT contain — the
// CONSOLE-1 inherited requirement that a cursor carries a position and never authority. Asserting on the
// opaque form would pass against any encoding that merely looked scrambled.
func DecodeCursorForTest(t interface{ Fatalf(string, ...any) }, encoded string) string {
	if _, err := decodeEventCursor(encoded); err != nil {
		t.Fatalf("decoding cursor %q: %v", encoded, err)
	}
	// THE RAW PAYLOAD, NOT A RECONSTRUCTION — and D481 got this wrong.
	//
	// This used to return fmt.Sprintf("%d:%d", c.ReceivedAt.UnixNano(), c.ID): a string rebuilt from the
	// struct's two fields, which STRUCTURALLY CANNOT contain a leaked role whatever the encoder writes.
	// The D481 mutation appeared to kill only because it also added a field to eventCursor and threaded
	// it through this helper — mutating the test infrastructure so the test could see the defect, which
	// is not a kill at all. Encoding a role in the ENCODER ALONE passed.
	//
	// Found by the CONSOLE-6b author hitting the same trap in its own first draft and checking whether
	// the shipped one shared it. It did.
	return rawCursorPayload(t, encoded)
}

// DecodeAlertCursorForTest and DecodeIncidentCursorForTest do the same for the CONSOLE-6b siblings, and
// they return the RAW DECODED PAYLOAD rather than the parsed struct's fields reformatted.
//
// That distinction is the difference between a real assertion and a vacuous one: a string rebuilt from
// `c.DetectedAt` and `c.ID` cannot contain a role no matter what the encoder wrote, so a test asserting
// on it would pass against a cursor that carried the caller's role in a fourth field. It is the bytes a
// client holds that must be free of authority, so it is the bytes that get asserted on. The cursor is
// still parsed first, so the payload examined is one the production decoder accepts.
func DecodeAlertCursorForTest(t interface{ Fatalf(string, ...any) }, encoded string) string {
	if _, err := decodeAlertCursor(encoded); err != nil {
		t.Fatalf("decoding alert cursor %q: %v", encoded, err)
	}
	return rawCursorPayload(t, encoded)
}

func DecodeIncidentCursorForTest(t interface{ Fatalf(string, ...any) }, encoded string) string {
	if _, err := decodeIncidentCursor(encoded); err != nil {
		t.Fatalf("decoding incident cursor %q: %v", encoded, err)
	}
	return rawCursorPayload(t, encoded)
}

func rawCursorPayload(t interface{ Fatalf(string, ...any) }, encoded string) string {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("cursor %q is not base64url: %v", encoded, err)
	}
	return string(raw)
}

// IsLoopStopForTest exposes the correlation loop's stop predicate. It is asserted directly because the
// case that matters — a real database error arriving in the same window as the leader's cancellation —
// is not reachable through the loop: DynamicLoop re-checks the context and returns before calling the
// work function, so the conjunction can only be exercised as a predicate.
func IsLoopStopForTest(ctx context.Context, err error) bool { return isLoopStop(ctx, err) }

// ITSMPhaseForTest exposes the ITSM phase classifier. It is asserted directly because the ordering of
// its cases is load-bearing: every specific case is ALSO wrapped in ErrTicketOpening, so testing the
// general one first would collapse an orphaned remote ticket into the bland "opening_tickets" label
// whose documented meaning is that nothing was left behind.
func ITSMPhaseForTest(err error) []slog.Attr { return itsmPhase(err) }
