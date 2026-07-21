package controlplane

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

// SetNotifier turns on alert delivery (D83). Without it the server records alerts
// but tells no one (the default Nop). Delivery is best-effort and additive — the
// recorded alert is the record, the notification is a copy pushed to a human (D30).
func (s *Server) SetNotifier(n notify.Notifier) { s.notifier = n }

// notify delivers an alert best-effort: a sink error is logged and COUNTED, never
// propagated — a down webhook must not break telemetry ingest or the detection
// itself. Losing a notification degrades responsiveness, not the record.
func (s *Server) emit(ctx context.Context, n notify.Notification) {
	if s.notifier == nil {
		return
	}
	if err := s.notifier.Notify(ctx, n); err != nil {
		s.NotifyFailures.Add(1)
		fmt.Fprintf(os.Stderr, "openshield-server: alert delivery failed (alert still recorded): %v\n", err)
	}
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
