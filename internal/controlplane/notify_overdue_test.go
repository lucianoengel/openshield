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

func (f *fakeNotifier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeNotifier) first() notify.Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[0]
}

// waitSent polls until the async delivery worker (SIEM-12) has delivered `want` notifications.
func waitSent(t *testing.T, f *fakeNotifier, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for f.count() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.count() != want {
		t.Fatalf("delivered %d notifications, want %d", f.count(), want)
	}
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
	if n != 1 {
		t.Fatalf("first check notified %d, want exactly 1 newly-overdue agent", n)
	}
	waitSent(t, fn, 1) // delivery is async (SIEM-12)
	if fn.first().Kind != notify.KindAgentOverdue || fn.first().AgentID != "stale" {
		t.Fatalf("delivered %+v, want an agent-overdue for 'stale'", fn.first())
	}
	if fn.first().ID == "" {
		t.Error("the delivered notification has no idempotency id (SIEM-12)")
	}

	// Second check: same agent still overdue → deduped, no new notification.
	n, err = srv.NotifyOverdue(ctx, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second check notified %d, want 0 (dedup)", n)
	}
	if fn.count() != 1 {
		t.Fatalf("dedup delivered again (total %d), want 1", fn.count())
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
