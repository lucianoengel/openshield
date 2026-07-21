package controlplane_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/notify"
)

type fakeNotifier struct {
	mu   sync.Mutex
	sent []notify.Notification
}

func (f *fakeNotifier) Notify(_ context.Context, n notify.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, n)
	return nil
}

// A stale agent triggers exactly one overdue notification; a second check dedups;
// after a fresh heartbeat the agent can alert again (D83).
func TestNotifyOverdueDeliversAndDedups(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	fn := &fakeNotifier{}
	srv.SetNotifier(fn)
	ctx := context.Background()

	// A stale agent: ENROLLED (in the roster) and last seen via VERIFIED telemetry 2 hours
	// ago (overdue past 15m). SEC-3: liveness is roster + verified telemetry only.
	seedRoster(t, pool, "stale")
	seedTelemetryRow(t, pool, "stale", true, time.Now().Add(-2*time.Hour))

	n, err := srv.NotifyOverdue(ctx, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(fn.sent) != 1 || fn.sent[0].Kind != notify.KindAgentOverdue || fn.sent[0].AgentID != "stale" {
		t.Fatalf("first check notified %d (%v), want exactly 1 agent-overdue for 'stale'", n, fn.sent)
	}

	// Second check: same agent still overdue → deduped, no new notification.
	n, err = srv.NotifyOverdue(ctx, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(fn.sent) != 1 {
		t.Fatalf("second check notified %d (total %d), want 0 (dedup)", n, len(fn.sent))
	}

	// The agent reports again (recent heartbeat) → recovers; then goes silent → it
	// can alert once more. Simulate recovery with a fresh row, then staleness by
	// making it old again.
	if _, err := pool.Exec(ctx, `UPDATE fleet_telemetry SET received_at = now() WHERE agent_id='stale'`); err != nil {
		t.Fatal(err)
	}
	if n, _ := srv.NotifyOverdue(ctx, 15*time.Minute); n != 0 {
		t.Fatalf("a recently-seen agent notified %d, want 0", n)
	}
	if _, err := pool.Exec(ctx, `UPDATE fleet_telemetry SET received_at = now() - interval '2 hours' WHERE agent_id='stale'`); err != nil {
		t.Fatal(err)
	}
	if n, _ := srv.NotifyOverdue(ctx, 15*time.Minute); n != 1 {
		t.Fatalf("after recovery+silence the agent notified %d, want 1 (eligible again)", n)
	}
}
