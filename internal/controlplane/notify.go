package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

// notifyDedupeWindow buckets a notification's timestamp so a logical alert re-detected within
// this window derives the SAME idempotency id and delivers once, while a genuinely new occurrence
// in a later window pages again (SIEM-12).
const notifyDedupeWindow = 10 * time.Minute

// dedupeSet is a bounded, FIFO-evicting set of recently-seen notification ids. It gives emit a
// server-side idempotency check without unbounded growth: the window-bucketed id ages out of
// relevance, and the size cap bounds memory regardless.
type dedupeSet struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
	cap   int
}

func newDedupeSet(capacity int) *dedupeSet {
	return &dedupeSet{seen: make(map[string]struct{}, capacity), cap: capacity}
}

// markNew records id and reports true if it was NOT already present (a genuinely new alert);
// false means this id was already emitted — a duplicate to suppress.
func (d *dedupeSet) markNew(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[id]; ok {
		return false
	}
	d.seen[id] = struct{}{}
	d.order = append(d.order, id)
	if len(d.order) > d.cap {
		evict := d.order[0]
		d.order = d.order[1:]
		delete(d.seen, evict)
	}
	return true
}

// SetNotifier turns on alert delivery (D83). Without it the server records alerts
// but tells no one (the default Nop). Delivery is best-effort and additive — the
// recorded alert is the record, the notification is a copy pushed to a human (D30).
// SetNotifier turns on alert delivery and starts the async delivery worker (once). Delivery runs
// OFF the ingest path (SIEM-12): emit enqueues, the worker delivers, so a slow/retrying webhook
// never stalls telemetry ingest (handleSigned → observePeer → emit).
func (s *Server) SetNotifier(n notify.Notifier) {
	s.notifier = n
	s.notifyOnce.Do(func() { go s.deliverLoop() })
}

// deliverLoop delivers queued notifications one at a time, off the ingest path. It runs for the
// process lifetime; a delivery error is counted and logged, never propagated (best-effort, D83).
func (s *Server) deliverLoop() {
	for n := range s.notifyQ {
		if s.notifier == nil {
			continue
		}
		if err := s.notifier.Notify(context.Background(), n); err != nil {
			s.NotifyFailures.Add(1)
			fmt.Fprintf(os.Stderr, "openshield-server: alert delivery failed (alert still recorded): %v\n", err)
		}
	}
}

// emit QUEUES an alert for async delivery (SIEM-12) — it does not deliver inline, so a slow webhook
// cannot stall ingest. It stamps a DETERMINISTIC idempotency id derived from the alert's content and
// time-window, then suppresses a duplicate server-side: the exact scenario it targets — an agent
// re-sends telemetry, the server re-detects and re-emits — pages exactly once, and the id it carries
// lets the receiver dedupe a client-timeout-after-server-success retry too. If the queue is full (a
// delivery backlog), the notification is DROPPED and counted — losing a page degrades responsiveness,
// never the record, and never blocks ingest.
func (s *Server) emit(_ context.Context, n notify.Notification) {
	if s.notifier == nil {
		return
	}
	if n.ID == "" {
		n.ID = notifyID(n)
	}
	// Server-side idempotency: a logical alert already emitted this window is suppressed, so a
	// re-detection does not double-page (SIEM-12). markNew is atomic (check-and-record).
	if s.notifyDedupe != nil && !s.notifyDedupe.markNew(n.ID) {
		s.NotifyDeduped.Add(1)
		return
	}
	select {
	case s.notifyQ <- n:
	default:
		s.NotifyDropped.Add(1)
		fmt.Fprintf(os.Stderr, "openshield-server: alert delivery queue full — dropped a notification (ingest never blocks)\n")
	}
}

// notifyID derives a STABLE idempotency key from the alert's identity — kind, subject, agent, and a
// bucketed timestamp (SIEM-12). The same logical alert re-emitted within notifyDedupeWindow yields
// the same id (so it dedupes); a new occurrence in a later window yields a new id (so it pages again).
// A caller that already set Notification.ID keeps it.
func notifyID(n notify.Notification) string {
	bucket := n.At.Truncate(notifyDedupeWindow).UTC().Unix()
	key := fmt.Sprintf("%s|%s|%s|%d", n.Kind, n.Subject, n.AgentID, bucket)
	sum := sha256.Sum256([]byte(key))
	return "ntf_" + hex.EncodeToString(sum[:12])
}

// NotifyOverdue notifies a human about agents that have gone silent past threshold
// (the dead-man's-switch, D50/D51), DEDUPLICATED: an agent is notified once when it
// goes overdue, and again only after it reports and goes silent a second time — so a
// long-silent agent does not page every interval. Returns how many were notified.
func (s *Server) NotifyOverdue(ctx context.Context, threshold time.Duration) (int, error) {
	overdue, err := s.Overdue(ctx, threshold, s.now())
	if err != nil {
		return 0, err
	}
	current := make([]string, 0, len(overdue))
	for _, a := range overdue {
		if a.Overdue {
			current = append(current, a.AgentID)
		}
	}

	s.notifyMu.Lock()
	fresh, next := newlyOverdue(s.notifiedOverdue, current)
	s.notifiedOverdue = next
	s.notifyMu.Unlock()

	for _, agentID := range fresh {
		s.emit(ctx, notify.Notification{Kind: notify.KindAgentOverdue, AgentID: agentID, At: s.now()})
	}
	return len(fresh), nil
}

// newlyOverdue is the pure dedup: given the previously-notified set and the current
// overdue agents, it returns the agents newly overdue (in current, not in prev) and
// the next set (exactly the current overdue agents — an agent that has recovered
// drops out, so it can alert again on a future silence).
func newlyOverdue(prev map[string]bool, current []string) (fresh []string, next map[string]bool) {
	next = make(map[string]bool, len(current))
	for _, id := range current {
		next[id] = true
		if !prev[id] {
			fresh = append(fresh, id)
		}
	}
	return fresh, next
}
