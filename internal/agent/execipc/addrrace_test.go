package execipc_test

import (
	"context"
	"sync"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/execipc"
	"github.com/lucianoengel/openshield/internal/agent/watchdog"
)

// Listen BLOCKS until ctx is done, so the only way to use it is in its own goroutine — which makes every
// call to Addr() a cross-goroutine read of state Listen writes. execipc gets this right (the field is
// written and read under s.mu); the sibling printguard server did NOT, and shipped a data race that only
// surfaced when a test finally called Addr() concurrently with Listen.
//
// This test exists so execipc cannot acquire the same defect quietly. It is deliberately unsynchronised
// against the bind: no sleep before the reads, and cancellation racing them, so the reader hammers Addr()
// during exactly the window where the listener is assigned and then closed.
//
// SHOWN TO CATCH IT: with s.mu removed from the write and from Addr, `go test -race` reports a data race
// on three runs of three. A concurrency test that has never been demonstrated to fail is a comment.
func TestAddrIsSafeToCallWhileListenIsStartingAndStopping(t *testing.T) {
	sock := socketPath(t, "ar.sock")
	s := &execipc.Server{Evaluate: func(context.Context, watchdog.PermissionEvent) (watchdog.Verdict, error) {
		return watchdog.VerdictAllow, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = s.Listen(ctx, sock) }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = s.Addr()
		}
	}()
	cancel()
	wg.Wait()
}
