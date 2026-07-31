// Package controlplane is the server side of OpenShield (T-023).
//
// It subscribes to the agent telemetry subjects and persists what it receives to
// a FLEET AGGREGATE store. This is deliberately NOT the agent's forward-secure
// audit ledger (D12/D30): the aggregate has no hash chain and no signatures, a
// compromised control plane could alter it, and the evidentiary record lives at
// the agent, externally anchored (T-019). The aggregate is a queryable
// convenience — "what did the fleet see" — and must never be presented as
// evidence.
//
// It coordinates and observes; it does NOT distribute policy or control agents
// (D14 — "the server coordinates, it does not control"). NATS lives here, never
// in core (D24).
package controlplane

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/analytics/peerueba"
	"github.com/lucianoengel/openshield/internal/config"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/notify"
	"github.com/lucianoengel/openshield/internal/runner"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// TelemetryRow is one persisted aggregate record.
type TelemetryRow struct {
	AgentID    string
	Kind       string
	EventID    string
	ReceivedAt time.Time
	Payload    []byte
}

// Server receives and persists agent telemetry.
type Server struct {
	pool *pgxpool.Pool

	mu       sync.Mutex
	subs     []*nats.Subscription
	conn     *nats.Conn
	natsOpts []nats.Option
	// sigSub is held separately from subs because it is the ONE subscription that can be rebuilt while the
	// server runs — see healIngest (PLAT-10). Everything in subs lives for the process.
	sigSub *nats.Subscription
	ingest ingestHealth
	// operatorOIDC verifies operator bearer tokens (ZT-7). Nil means certificate-only, the default.
	operatorOIDC operatorTokenVerifier

	// DecodeFailures counts messages that did not decode. A malformed message is
	// dropped so it cannot stall the subscription, but it is COUNTED so the drop
	// is observable — a silent vanish would be the missing-evidence failure the
	// system exists to prevent.
	DecodeFailures atomic.Int64
	// RejectedTelemetry counts signed telemetry that failed verification (bad
	// signature, unknown/revoked agent, replay) — rejected, never silent.
	RejectedTelemetry atomic.Int64
	// Gaps counts sequence gaps in verified telemetry (suppression between an
	// agent and here).
	Gaps atomic.Int64
	// PeerAlerts counts server-side peer-UEBA detections recorded (D54).
	PeerAlerts atomic.Int64
	// NotifyFailures counts alert-delivery errors (D83). Delivery is best-effort —
	// a failure is counted, never fatal — so this counter is how a broken sink is
	// observable rather than silent.
	NotifyFailures atomic.Int64
	// NotifyDropped counts notifications dropped because the async delivery queue was full
	// (SIEM-12) — a delivery backlog degrades responsiveness but never blocks ingest.
	NotifyDropped atomic.Int64
	// NotifyDeduped counts notifications suppressed because the same logical alert (same
	// deterministic id) was already delivered this window (SIEM-12) — a client-timeout-after-
	// server-success retry re-detects and re-emits, but pages exactly once.
	NotifyDeduped atomic.Int64
	// DroppedMessages counts NATS async errors (above all SlowConsumer overflow) — a
	// receive-side drop is COUNTED and logged, never silent (SEC-4).
	DroppedMessages atomic.Int64

	// notifier delivers alerts to a human (D83). Default Nop (delivery off);
	// backfilling is non-zero while a retrospective correlation run is in progress (SOAR-10), which
	// suppresses paging. A COUNTER rather than a bool so two concurrent backfills cannot have the
	// first to finish un-silence the second — the pager would then ring for a range still being
	// replayed, which is the one outcome the suppression exists to prevent.
	backfilling atomic.Int64
	// SetNotifier turns it on. notifiedOverdue dedups overdue notifications so a
	// silent agent alerts once, not every check.
	notifier        notify.Notifier
	notifyMu        sync.Mutex
	notifiedOverdue map[string]bool
	// notifyQ carries alerts to the async delivery worker (SIEM-12), started once by SetNotifier —
	// delivery runs OFF the ingest path so a slow webhook never stalls telemetry ingest.
	notifyQ    chan notify.Notification
	notifyOnce sync.Once
	// notifyRunning is true once the delivery loop has been started (by SetNotifier).
	// emit enqueues only when it is true, so an unconfigured server never fills the
	// queue (R34-9).
	notifyRunning atomic.Bool
	// notifyDedupe is a bounded set of recently-emitted notification ids, so the same logical
	// alert delivers once even if it is re-detected and re-emitted (SIEM-12). Bounded (FIFO
	// eviction) so it cannot grow without limit.
	notifyDedupe *dedupeSet

	// peer-UEBA (D54) is a SERVER-SIDE analytics consumer of the verified stream,
	// OFF unless explicitly enabled — enabling it is the D23 consent/DPIA decision.
	// analyzer is nil when disabled; when set, a verified `event` feeds the
	// subject's peer baseline and an above-threshold subject raises a peer alert,
	// throttled per-subject by peerCooldown (a rising-edge limiter, not a signal
	// change). It OBSERVES; it never feeds risk back to agents (D14).
	analyzer      *peerueba.Analyzer
	peerThreshold float64
	peerCooldown  time.Duration
	peerMu        sync.Mutex
	peerLastAlert map[string]time.Time
	now           func() time.Time

	// riskSigner signs published risk updates (SEC-1) so the gateway can verify a risk
	// update came from the control plane, not a forging publisher. nil = risk publishing
	// off (PublishRisk does not emit an unsigned update the gateway would reject anyway).
	riskSigner ed25519.PrivateKey
	// intentSigner signs published Response-Intents (SOAR-7). Without it PublishIntents refuses: an
	// unsigned containment signal is a forgery target, not a convenience.
	intentSigner ed25519.PrivateKey

	// configResolver is the PROCESS's resolver, installed by the command. The configuration surface
	// validates and reports against it, so what an operator reads is what this binary is honouring.
	configResolver *config.Resolver
	// intentBlastRadius caps how many subjects one publication run may target; 0 = no ceiling.
	intentBlastRadius int

	// graph is the XDR entity graph (XDR-1-WIRE): enrollment and verified telemetry ingest resolve a
	// device entity into it so every domain's detections coalesce onto one entity. It is a DERIVED
	// index (D38), never the system of record — a write failure is counted, never fatal.
	graph *xdr.Store
	// EntityResolveFailures counts best-effort entity-graph writes that failed — a non-zero value
	// means some device/user did not land in the graph, observable rather than silent.
	EntityResolveFailures atomic.Int64

	// SIEM-9 WIDENED THESE, and the names are now narrower than the meaning: the listener accepts CEF
	// AND RFC 5424, so Dropped counts lines that parsed as NEITHER — not "was not CEF". The names are
	// kept because they are exposed on /metrics and renaming them would break every dashboard built on
	// them; the meaning is documented here and in the metric help text instead.
	//
	// THAT SENTENCE WAS FALSE WHEN IT WAS WRITTEN (D348): these counters were incremented and rendered
	// by NOTHING, so no dashboard could have been built on them. It is true now — they are exposed, and
	// a guard test fails the build if any declared counter stops being. The comment is left standing
	// rather than rewritten because the reason it gave for keeping the names is still the right reason.
	//
	// A pre-existing test caught this widening: its "non-CEF" fixture was a valid RFC 5424 line, so it
	// became ingested rather than dropped. That was the change working, and the fixture — not the
	// assertion — was what needed updating.
	//
	// CEFIngested / CEFDropped count external logs (SIEM-4/SIEM-9) that were persisted vs.
	// skipped (a non-CEF/malformed datagram, or a persist failure) — the drop is counted, never silent.
	CEFIngested   atomic.Int64
	CEFDropped    atomic.Int64
	cefListenAddr atomic.Value // string: the bound listener address, once RunCEFSyslog binds
	// cefDatagram / cefStream hold the running syslog listeners so /metrics can read the counters
	// they keep for what they REFUSED — rate-limited, over-bound, unparseable. Published atomically
	// because a metrics scrape can race startup, and absent (not zero) when no listener runs: a
	// listener that is not configured and one that is refusing nothing are different claims, and a
	// dashboard cannot tell zero from absent.
	cefDatagram atomic.Value // *syslog.Listener
	cefStream   atomic.Value // *syslog.StreamListener

	// CloudTrailIngested / CloudTrailDropped count CloudTrail records persisted vs. skipped (a record
	// with no event identity, a poison file, or a persist failure) — the drop is counted, never silent.
	CloudTrailIngested atomic.Int64
	CloudTrailDropped  atomic.Int64

	// WEFIngested / WEFDropped count Windows Event Forwarding events persisted vs. skipped (a record with
	// no EventID, a poison file, or a persist failure) — the drop is counted, never silent.
	WEFIngested atomic.Int64
	WEFDropped  atomic.Int64

	// UnifiedAlertFailures counts unified-alert projections that could not be recorded (no graph, an
	// entity-resolve failure, or an insert error) — the derived cross-domain stream is best-effort over
	// the authoritative per-domain records, so a failure is counted, never fatal (XDR-2).
	UnifiedAlertFailures atomic.Int64
	// DecisionContractViolations counts decisions refused because they do not satisfy the decision
	// contract — an action outside the closed set, a confidence absent or out of range, no identifying
	// policy (D350). A verified signature says WHO sent it, not that what they sent is expressible.
	DecisionContractViolations atomic.Int64

	// UnprojectedDecisions counts VERIFIED alertable decisions that could not be projected into the
	// unified stream — no persisted originating event, a subject-less event, or an unmapped event kind
	// (XDR-2). Distinct from UnifiedAlertFailures: nothing failed, the decision simply could not be
	// keyed to an entity, so it was dropped rather than grouped wrongly. A rising value means a domain
	// is silently not reaching correlation, which otherwise only shows up as an empty incident list.
	UnprojectedDecisions atomic.Int64
	// SOAR-8: RunnerActions counts IRREVERSIBLE external actions performed; RunnerRefusals counts intents
	// the runner declined (unapproved, expired, undeclared verb, already enacted). Both matter: a
	// responder that silently does nothing and one that silently does everything look identical without
	// them.
	RunnerActions  atomic.Int64
	RunnerRefusals atomic.Int64
	responderKey   ed25519.PublicKey
	responder      *runner.Connector

	// RetentionRecordFailures counts retention compliance events that could not be recorded (SIEM-10) —
	// the purge still happened, so a recording failure is counted (the report gap is observable), not
	// fatal.
	RetentionRecordFailures atomic.Int64
}

// New creates a server over an existing pool.
func New(pool *pgxpool.Pool) *Server {
	return &Server{pool: pool, now: time.Now, notifier: notify.Nop{}, notifiedOverdue: map[string]bool{},
		notifyQ: make(chan notify.Notification, 256), notifyDedupe: newDedupeSet(4096),
		graph: xdr.NewStore(pool)}
}

// SetEntityGraph overrides the XDR entity graph (XDR-1-WIRE). New() already builds one from the
// server's pool; this exists so a test can install a graph over a deliberately-broken pool to exercise
// the best-effort failure path without mutating the shared schema.
func (s *Server) SetEntityGraph(g *xdr.Store) { s.graph = g }

// resolveDeviceEntity resolves the device entity for a canonical subject in the XDR graph,
// BEST-EFFORT (XDR-1-WIRE): an empty subject or a graph error is counted and dropped, never
// propagated — the graph is a derived index, so a write failure must not break the primary action.
//
// It goes through entityForSubject rather than Resolve directly, so a subject another domain already
// registered under a different kind (the gateway's user identity) is NOT re-minted as a second device
// alias on its own entity — see entityForSubject for why that fork silently costs a domain.
func (s *Server) resolveDeviceEntity(ctx context.Context, subject string) {
	if s.graph == nil || subject == "" {
		return
	}
	if _, err := s.entityForSubject(ctx, xdr.KindDevice, subject); err != nil {
		s.EntityResolveFailures.Add(1)
		fmt.Fprintf(os.Stderr, "openshield-server: entity-graph device resolve failed (subject %s): %v\n", subject, err)
	}
}

// EnablePeerUEBA turns on server-side peer-baseline analytics (D54). This is the
// D23 consent/DPIA decision, made deliberately by an operator — NOT a default:
// without this call the control plane observes no subject and records no peer
// alert. threshold is the peer-relative risk [0,1] at which a subject alerts;
// cooldown throttles repeat alerts for a still-anomalous subject.
func (s *Server) EnablePeerUEBA(threshold float64, cooldown time.Duration) {
	// SEC-10: reserve a monotonic context-version BLOCK so this run's versions never collide
	// with a prior run's (D27). Best-effort — if the reservation fails (e.g. a very old
	// schema), start at 0 and log; a collision is worse only across restarts, not fatal.
	base, err := s.reserveVersionBase(context.Background(), versionBlockSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA version base reservation failed (%v) — starting at 0\n", err)
	}
	// SIEM-5: reload the persisted baseline so a restart resumes the warm baseline instead of
	// cold-starting (which would blind the fleet to peer anomalies for a decay half-life).
	// Best-effort — a load failure logs and starts cold; failing to ENABLE detection because a
	// baseline couldn't load would be the worse outcome. Loaded before the analyzer observes any
	// event (EnablePeerUEBA runs at startup), so there is no race with the ingest stream.
	opts := []peerueba.Option{peerueba.WithStartVersion(base)}
	if states, lerr := s.loadBaselines(context.Background()); lerr != nil {
		fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA baseline load failed (%v) — starting cold\n", lerr)
	} else if len(states) > 0 {
		opts = append(opts, peerueba.WithSnapshot(states))
		fmt.Fprintf(os.Stderr, "openshield-server: peer-UEBA resumed %d persisted baseline(s)\n", len(states))
	}
	s.analyzer = peerueba.New(opts...)
	s.peerThreshold = threshold
	s.peerCooldown = cooldown
	s.peerLastAlert = map[string]time.Time{}
}

// PersistBaselines snapshots the peer-UEBA baseline and UPSERTs it into ueba_baselines (SIEM-5),
// so a restart can resume it. A no-op when peer-UEBA is disabled. Idempotent per subject
// (ON CONFLICT). Best-effort at the call site: the caller (a periodic loop / shutdown) logs an
// error and continues — a failed persist only shortens the next restart's warm window.
func (s *Server) PersistBaselines(ctx context.Context) error {
	if s.analyzer == nil {
		return nil
	}
	// Bound growth (SIEM-5b): drop cold (decayed-below-ε) subjects from the map, and delete their
	// rows below, so neither the map nor the table grows without limit.
	pruned := s.analyzer.Prune(peerueba.PruneThreshold)
	states := s.analyzer.Snapshot()

	// Atomic: the pruned deletes and the surviving upserts commit together (SIEM-5b) — a crash
	// mid-persist leaves the prior consistent baseline, and it is one round-trip batch, not N.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("persisting baselines: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	for _, id := range pruned {
		if _, err := tx.Exec(ctx, `DELETE FROM ueba_baselines WHERE subject = $1`, id); err != nil {
			return fmt.Errorf("pruning a baseline row: %w", err)
		}
	}
	for _, st := range states {
		if _, err := tx.Exec(ctx,
			`INSERT INTO ueba_baselines (subject, count, last_seen, updated_at)
			 VALUES ($1, $2, $3, now())
			 ON CONFLICT (subject) DO UPDATE
			   SET count = EXCLUDED.count, last_seen = EXCLUDED.last_seen, updated_at = now()`,
			st.Subject, st.Count, st.Last); err != nil {
			return fmt.Errorf("persisting baseline for a subject: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// loadBaselines reads the persisted peer-UEBA baseline for restore (SIEM-5). Returns an empty
// slice (not an error) when the table is empty — a cold fleet.
func (s *Server) loadBaselines(ctx context.Context) ([]peerueba.SubjectState, error) {
	rows, err := s.pool.Query(ctx, `SELECT subject, count, last_seen FROM ueba_baselines`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := s.now()
	var out []peerueba.SubjectState
	for rows.Next() {
		var st peerueba.SubjectState
		if err := rows.Scan(&st.Subject, &st.Count, &st.Last); err != nil {
			return nil, err
		}
		// Validate on load (SIEM-5b): a corrupt row (non-finite/negative count, or a last-seen in the
		// future beyond a clock-skew grace — reachable only with DB write access) is skipped, so it
		// never enters the analyzer. A skipped subject simply starts cold.
		if math.IsNaN(st.Count) || math.IsInf(st.Count, 0) || st.Count < 0 || st.Last.After(now.Add(time.Minute)) {
			continue
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// CurrentContextVersion returns the peer-UEBA context version for a subject, or "" when
// peer-UEBA is disabled. Exposed so an operator (and a test) can see which context version is
// currently in force — it moves into a new run's reserved block across restarts (SEC-10).
func (s *Server) CurrentContextVersion(subject string) string {
	if s.analyzer == nil {
		return ""
	}
	c := s.analyzer.ContextFor(subject)
	if c == nil {
		return ""
	}
	return c.Version
}

// ObserveForTest feeds a subject to the peer-UEBA analyzer directly (test seam for SEC-10).
func (s *Server) ObserveForTest(subject string) {
	if s.analyzer != nil {
		s.analyzer.Observe(subject)
	}
}

// LoadBaselinesForTest exposes loadBaselines so a test can assert the on-load validation (SIEM-5b)
// filters a corrupt/future row before it reaches the analyzer.
func LoadBaselinesForTest(s *Server, ctx context.Context) ([]peerueba.SubjectState, error) {
	return s.loadBaselines(ctx)
}

// RecordPeerAlertForTest exposes the peer-alert write path so a test can assert the first-class
// lifecycle fields it stamps (severity/status/dedup_key, SIEM-6b).
func RecordPeerAlertForTest(s *Server, ctx context.Context, subject string, risk float64, ctxVersion, agentID string, at time.Time) error {
	return s.recordPeerAlert(ctx, subject, risk, ctxVersion, agentID, at)
}

// PeerRiskForTest returns a subject's current peer-relative risk, or -1 when peer-UEBA is
// disabled or the subject has no baseline (a test seam for SIEM-5's restart survival).
func PeerRiskForTest(s *Server, subject string) float64 {
	if s.analyzer == nil {
		return -1
	}
	c := s.analyzer.ContextFor(subject)
	if c == nil {
		return -1
	}
	return c.RiskScore
}

// versionBlockSize is how much context-version space each startup reserves. Large enough that
// no single run exhausts it, so within a run the counter never overruns into the next run's
// reserved block.
const versionBlockSize = 1_000_000_000

// reserveVersionBase atomically reserves the next context-version block and returns its base
// (SEC-10). The reservation is the same forward-monotonic pattern as the ledger sequence
// (D66): each call bumps the persisted high-water by the block size and returns the old value.
func (s *Server) reserveVersionBase(ctx context.Context, block uint64) (uint64, error) {
	var base int64
	err := s.pool.QueryRow(ctx,
		`UPDATE peerueba_version SET next_base = next_base + $1 WHERE id = 1 RETURNING next_base - $1`,
		int64(block)).Scan(&base)
	if err != nil {
		return 0, err
	}
	return uint64(base), nil
}

// NATSOptions are applied to the control plane's NATS connection — used to pass
// nats.Secure(clientConfig) for mutual TLS (D55). Empty means a plaintext
// connection, unchanged from before.
func (s *Server) SetNATSOptions(opts ...nats.Option) { s.natsOpts = opts }

// natsErrorHandler counts and loudly logs asynchronous NATS errors — above all a
// SlowConsumer, which is a subscription's pending queue OVERFLOWING and messages being
// DROPPED (SEC-4). The send side has spool + gap detection; the receive side had NOTHING —
// a slow DB insert per message could overflow the client buffer and lose telemetry
// SILENTLY and uncounted, violating the project's own "no silent loss" invariant. This
// makes the drop OBSERVABLE via DroppedMessages, never a silent vanish.
func (s *Server) natsErrorHandler(_ *nats.Conn, sub *nats.Subscription, err error) {
	s.DroppedMessages.Add(1)
	subject := ""
	if sub != nil {
		subject = sub.Subject
	}
	fmt.Fprintf(os.Stderr, "openshield-server: NATS async error (message(s) may be DROPPED) subject=%q: %v\n", subject, err)
}

// pendingMsgLimit/pendingBytesLimit bound each subscription's client-side queue explicitly,
// so overflow behaviour is deterministic (and fires the ErrorHandler) rather than relying on
// the library default. Generous, but bounded — an unbounded queue on a slow consumer is an
// OOM, a too-small one drops needlessly.
const (
	pendingMsgLimit   = 65536
	pendingBytesLimit = 64 << 20 // 64 MiB
)

// subscribeCounted subscribes and applies explicit pending limits so a slow consumer
// overflows into the ErrorHandler (counted) rather than dropping silently (SEC-4).
func (s *Server) subscribeCounted(conn *nats.Conn, subject string, cb nats.MsgHandler) (*nats.Subscription, error) {
	sub, err := conn.Subscribe(subject, cb)
	if err != nil {
		return nil, err
	}
	if err := sub.SetPendingLimits(pendingMsgLimit, pendingBytesLimit); err != nil {
		return nil, fmt.Errorf("controlplane: pending limits on %s: %w", subject, err)
	}
	return sub, nil
}

// Connect attaches a broker connection WITHOUT subscribing to anything.
//
// For the operator-local subcommands, which need to PUBLISH one message and exit. Run() would subscribe
// this short-lived process to every telemetry subject and start consuming the fleet's stream, which is
// both wasteful and wrong: a CLI invocation must not become a competing consumer.
func (s *Server) Connect(natsURL string) error {
	opts := append([]nats.Option{}, s.natsOpts...)
	opts = append(opts, nats.ErrorHandler(s.natsErrorHandler))
	conn, err := nats.Connect(natsURL, opts...)
	if err != nil {
		return fmt.Errorf("controlplane: connecting to NATS: %w", err)
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	return nil
}

// Run connects to NATS and subscribes to the telemetry subjects until the
// context is cancelled.
func (s *Server) Run(ctx context.Context, natsURL string) error {
	// SEC-4: install an async ErrorHandler so a SlowConsumer drop is counted + logged, not
	// silent. Appended to any caller-supplied options (mTLS, D55).
	//
	// AND RETRY FOREVER. The default policy gives up after ~2 minutes, and for THIS process that is not
	// one endpoint going quiet — it is the whole fleet's ingest stopping, permanently, with the server
	// still running and reporting nothing wrong. Deliberately NOT applied in Connect() above: that path
	// exists for operator subcommands that publish one message and exit, where giving up promptly is the
	// correct behaviour and retrying forever would hang a CLI.
	opts := append([]nats.Option{}, s.natsOpts...)
	opts = append(opts, nats.ErrorHandler(s.natsErrorHandler))
	opts = append(opts, natsx.ResilienceOptions(func(msg string) {
		fmt.Fprintf(os.Stderr, "openshield-server: nats: %s\n", msg)
	})...)
	conn, err := nats.Connect(natsURL, opts...)
	if err != nil {
		return fmt.Errorf("controlplane: connecting to NATS: %w", err)
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	// SOAR-8: the intent responder, if configured. Wired here because the Server owns this connection.
	if err := s.subscribeIntentResponder(conn); err != nil {
		return fmt.Errorf("controlplane: subscribing the intent responder: %w", err)
	}

	subjects := []struct {
		subject string
		kind    string
	}{
		{natsx.SubjectEvents, "event"},
		{natsx.SubjectClassification, "classification"},
		{natsx.SubjectDecisions, "decision"},
	}
	for _, sc := range subjects {
		kind := sc.kind
		sub, err := s.subscribeCounted(conn, sc.subject, func(m *nats.Msg) {
			s.handle(context.Background(), kind, m.Data)
		})
		if err != nil {
			return fmt.Errorf("controlplane: subscribing %s: %w", sc.subject, err)
		}
		s.mu.Lock()
		s.subs = append(s.subs, sub)
		s.mu.Unlock()
	}

	// Heartbeats (T-018) update last-seen so a silent agent is detectable.
	hbSub, err := s.subscribeCounted(conn, natsx.SubjectHeartbeat, func(m *nats.Msg) {
		s.recordHeartbeat(context.Background(), m.Data)
	})
	if err != nil {
		return fmt.Errorf("controlplane: subscribing heartbeats: %w", err)
	}
	s.mu.Lock()
	s.subs = append(s.subs, hbSub)
	s.mu.Unlock()

	// Signed telemetry (T-017): verified against the enrolled key before persist. When JetStream is
	// enabled (PLAT-2), a durable explicit-ack consumer delivers it and we ACK only after persist — a
	// message published while this consumer was down is redelivered, not lost. Otherwise the core-NATS
	// subscription (auto-ack, at-most-once) is unchanged.
	var sigSub *nats.Subscription
	if natsx.JetStreamEnabled() {
		// PLAT-2: durable ingest is the DEFAULT, so an unavailable JetStream stops the control plane with
		// an error naming the opt-out — the same fail-fast the producers use. Silently subscribing over core
		// NATS instead would accept at-most-once telemetry in a deployment that believes it is durable.
		js, jerr := conn.JetStream()
		if jerr != nil {
			return fmt.Errorf("controlplane: durable ingest is the default but this broker has no JetStream: %w"+
				" — enable it (nats-server -js) or set OPENSHIELD_JETSTREAM=0 to accept at-most-once delivery", jerr)
		}
		if serr := natsx.EnsureTelemetryStream(js); serr != nil {
			return fmt.Errorf("controlplane: ensuring the telemetry stream: %w"+
				" — enable JetStream on the broker (nats-server -js) or set OPENSHIELD_JETSTREAM=0", serr)
		}
		sigSub, err = s.subscribeSignedDurable(js)
	} else {
		sigSub, err = s.subscribeCounted(conn, natsx.SubjectSigned, func(m *nats.Msg) {
			s.handleSigned(context.Background(), m.Data)
		})
	}
	if err != nil {
		return fmt.Errorf("controlplane: subscribing signed telemetry: %w", err)
	}
	s.mu.Lock()
	s.sigSub = sigSub
	s.mu.Unlock()

	// PLAT-10: keep the durable consumer alive. Without this, a broker that returns with empty JetStream
	// state leaves the fleet's ingest permanently dead and silent — the stream was only ever created here,
	// at startup.
	if natsx.JetStreamEnabled() {
		go s.healIngest(ctx, conn, func(js nats.JetStreamContext) error {
			sub, serr := s.subscribeSignedDurable(js)
			if serr != nil {
				return serr
			}
			s.mu.Lock()
			old := s.sigSub
			s.sigSub = sub
			s.mu.Unlock()
			if old != nil {
				// Best-effort: the old subscription's consumer is already gone, so this normally errors.
				// Dropping it anyway rather than leaking the client-side object.
				_ = old.Unsubscribe()
			}
			return nil
		})
	}

	<-ctx.Done()
	return s.Close()
}

// subscribeSignedDurable creates the durable explicit-ack subscription for signed telemetry. Extracted from
// Run so healIngest can rebuild it: the config has to be identical on a repair, and two copies of it would
// drift the moment one is edited.
func (s *Server) subscribeSignedDurable(js nats.JetStreamContext) (*nats.Subscription, error) {
	return js.Subscribe(natsx.SubjectSigned, func(m *nats.Msg) {
		switch s.handleSigned(context.Background(), m.Data) {
		case ingestTransient:
			// R34-4: redeliver with BACKOFF, not immediately — a bare Nak() hot-loops a
			// verified message against a down/full database, spinning CPU and drowning
			// the log. Delay grows with the redelivery count so a sustained DB outage is
			// retried patiently (never dropped), a transient blip still recovers fast.
			delay := nakBackoffBase
			if md, merr := m.Metadata(); merr == nil && md != nil {
				delay = backoffFor(md.NumDelivered)
			}
			_ = m.NakWithDelay(delay)
		default: // ingestPersisted or ingestPermanent — done, do not redeliver
			_ = m.Ack()
		}
	}, nats.Durable(natsx.TelemetryDurable), nats.ManualAck(), nats.AckExplicit())
}

// handle decodes a message for its index fields and persists the raw payload.
func (s *Server) handle(ctx context.Context, kind string, data []byte) {
	agentID, eventID, ok := decodeIndex(kind, data)
	if !ok {
		s.DecodeFailures.Add(1)
		return
	}
	if err := s.insert(ctx, kind, agentID, eventID, data, false); err != nil {
		// A persistence failure is also not silent — count it as a decode/handle
		// failure so a full store or a down database is observable.
		s.DecodeFailures.Add(1)
	}
}

// decodeIndex extracts the agent and event ids used for indexing. The payload is
// stored raw regardless — decoding is only to know where to file it.
func decodeIndex(kind string, data []byte) (agentID, eventID string, ok bool) {
	switch kind {
	case "event":
		var e corev1.Event
		if err := proto.Unmarshal(data, &e); err != nil {
			return "", "", false
		}
		return e.GetAgentId(), e.GetEventId(), true
	case "classification":
		var c corev1.ClassificationSummary
		if err := proto.Unmarshal(data, &c); err != nil {
			return "", "", false
		}
		// ClassificationSummary carries no agent id; keyed by event.
		return "", c.GetEventId(), true
	case "decision":
		var d corev1.Decision
		if err := proto.Unmarshal(data, &d); err != nil {
			return "", "", false
		}
		return "", d.GetEventId(), true
	default:
		return "", "", false
	}
}

func (s *Server) insert(ctx context.Context, kind, agentID, eventID string, payload []byte, verified bool) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified) VALUES ($1,$2,$3,$4,$5)`,
		agentID, kind, eventID, payload, verified)
	return err
}

// insertTx is the transactional telemetry insert used by the durable ingest path (R34-4), so the
// insert commits (or rolls back) ATOMICALLY with the sequence advance in verifySignedTx.
func (s *Server) insertTx(ctx context.Context, tx pgx.Tx, kind, agentID, eventID string, payload []byte, verified bool) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO fleet_telemetry (agent_id, kind, event_id, payload, verified) VALUES ($1,$2,$3,$4,$5)`,
		agentID, kind, eventID, payload, verified)
	return err
}

// Telemetry returns rows for an agent, oldest first.
func (s *Server) Telemetry(ctx context.Context, agentID string) ([]TelemetryRow, error) {
	return s.query(ctx, `SELECT agent_id, kind, event_id, received_at, payload
		FROM fleet_telemetry WHERE agent_id = $1 ORDER BY id ASC`, agentID)
}

// TelemetryForEvent returns rows for an event id, oldest first.
func (s *Server) TelemetryForEvent(ctx context.Context, eventID string) ([]TelemetryRow, error) {
	return s.query(ctx, `SELECT agent_id, kind, event_id, received_at, payload
		FROM fleet_telemetry WHERE event_id = $1 ORDER BY id ASC`, eventID)
}

func (s *Server) query(ctx context.Context, sql, arg string) ([]TelemetryRow, error) {
	rows, err := s.pool.Query(ctx, sql, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TelemetryRow
	for rows.Next() {
		var r TelemetryRow
		if err := rows.Scan(&r.AgentID, &r.Kind, &r.EventID, &r.ReceivedAt, &r.Payload); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PurgeOlderThan enforces the fleet-aggregate retention window (D81): it hard-DELETEs
// received telemetry and derived peer alerts older than cutoff, returning the total
// rows removed. A hard delete is correct here — the fleet aggregate is a DERIVED
// detection view, re-derivable from the stream, NOT the evidentiary forward-secure
// ledger (D38), which tombstones instead to stay chain-verifiable (D36). Without this,
// personal-adjacent telemetry accrues indefinitely, the posture D20 forbids.
func (s *Server) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	var total int64
	for _, q := range []struct{ table, col string }{
		{"fleet_telemetry", "received_at"},
		{"peer_alerts", "detected_at"},
	} {
		tag, err := s.pool.Exec(ctx,
			"DELETE FROM "+q.table+" WHERE "+q.col+" < $1", cutoff.UTC())
		if err != nil {
			return total, fmt.Errorf("controlplane: purge %s: %w", q.table, err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

// Close unsubscribes and closes the NATS connection. The pool is the caller's.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range s.subs {
		_ = sub.Unsubscribe()
	}
	s.subs = nil
	if s.sigSub != nil {
		_ = s.sigSub.Unsubscribe()
		s.sigSub = nil
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	return nil
}
