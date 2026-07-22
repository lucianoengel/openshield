package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/notify"
)

type blockingNotifier struct {
	block chan struct{}
	gotID chan string
}

func (b *blockingNotifier) Notify(_ context.Context, n notify.Notification) error {
	b.gotID <- n.ID
	<-b.block // delivery blocks forever
	return nil
}

// SIEM-12: emit must NOT block on delivery — it runs off the ingest path. Even when the sink blocks
// indefinitely, emit returns immediately, and the queued notification carries a stamped idempotency id.
func TestEmitDoesNotBlockIngest(t *testing.T) {
	bn := &blockingNotifier{block: make(chan struct{}), gotID: make(chan string, 1)}
	s := &Server{notifyQ: make(chan notify.Notification, 256)}
	s.SetNotifier(bn)

	done := make(chan struct{})
	go func() {
		s.emit(context.Background(), notify.Notification{Kind: notify.KindPeerAlert, Subject: "x"})
		close(done)
	}()
	select {
	case <-done: // emit returned promptly despite the blocked sink
	case <-time.After(1 * time.Second):
		t.Fatal("emit blocked on a slow sink — notify is still synchronous on the ingest path")
	}

	// The worker picked it up and is blocked in Notify; the delivered notification has an id (SIEM-12).
	select {
	case id := <-bn.gotID:
		if id == "" {
			t.Error("the queued notification has no idempotency id")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("the async delivery worker did not pick up the queued notification")
	}
	close(bn.block)
}
