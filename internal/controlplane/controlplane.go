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
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/notify"
	"github.com/lucianoengel/openshield/internal/xdr"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
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

	// graph is the XDR entity graph (XDR-1-WIRE): enrollment and verified telemetry ingest resolve a
	// device entity into it so every domain's detections coalesce onto one entity. It is a DERIVED
	// index (D38), never the system of record — a write failure is counted, never fatal.
	graph *xdr.Store
	// EntityResolveFailures counts best-effort entity-graph writes that failed — a non-zero value
	// means some device/user did not land in the graph, observable rather than silent.
	EntityResolveFailures atomic.Int64

	// CEFIngested / CEFDropped count CEF-over-syslog external logs (SIEM-4) that were persisted vs.
	// skipped (a non-CEF/malformed datagram, or a persist failure) — the drop is counted, never silent.
	CEFIngested   atomic.Int64
	CEFDropped    atomic.Int64
	cefListenAddr atomic.Value // string: the bound listener address, once RunCEFSyslog binds

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

// resolveDeviceEntity resolves (find-or-create) the device entity for a canonical subject in the XDR
// graph, BEST-EFFORT (XDR-1-WIRE): an empty subject or a graph error is counted and dropped, never
// propagated — the graph is a derived index, so a write failure must not break the primary action.
func (s *Server) resolveDeviceEntity(ctx context.Context, subject string) {
	if s.graph == nil || subject == "" {
		return
	}
	if _, err := s.graph.Resolve(ctx, xdr.KindDevice, subject); err != nil {
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

// Run connects to NATS and subscribes to the telemetry subjects until the
// context is cancelled.
func (s *Server) Run(ctx context.Context, natsURL string) error {
	// SEC-4: install an async ErrorHandler so a SlowConsumer drop is counted + logged, not
	// silent. Appended to any caller-supplied options (mTLS, D55).
	opts := append([]nats.Option{}, s.natsOpts...)
	opts = append(opts, nats.ErrorHandler(s.natsErrorHandler))
	conn, err := nats.Connect(natsURL, opts...)
	if err != nil {
		return fmt.Errorf("controlplane: connecting to NATS: %w", err)
	}
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

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
		js, jerr := conn.JetStream()
		if jerr != nil {
			return fmt.Errorf("controlplane: JetStream context: %w", jerr)
		}
		if serr := natsx.EnsureTelemetryStream(js); serr != nil {
			return fmt.Errorf("controlplane: ensuring telemetry stream: %w", serr)
		}
		sigSub, err = js.Subscribe(natsx.SubjectSigned, func(m *nats.Msg) {
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
	} else {
		sigSub, err = s.subscribeCounted(conn, natsx.SubjectSigned, func(m *nats.Msg) {
			s.handleSigned(context.Background(), m.Data)
		})
	}
	if err != nil {
		return fmt.Errorf("controlplane: subscribing signed telemetry: %w", err)
	}
	s.mu.Lock()
	s.subs = append(s.subs, sigSub)
	s.mu.Unlock()

	<-ctx.Done()
	return s.Close()
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
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	return nil
}
