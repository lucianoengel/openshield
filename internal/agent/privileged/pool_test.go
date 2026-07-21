package privileged_test

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/agent/privileged"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func buildWorker(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "openshield-worker")
	if out, err := exec.Command("go", "build", "-o", bin, "../../../cmd/openshield-worker").CombinedOutput(); err != nil {
		t.Fatalf("building worker: %v\n%s", err, out)
	}
	return bin
}

func cpfContentReq(id string) *corev1.ClassifyRequest {
	return &corev1.ClassifyRequest{
		RequestId: id, EventId: id,
		Subject: &corev1.ClassifyRequest_Content{Content: []byte("cpf 111.444.777-35\n")},
	}
}

func assertCPF(t *testing.T, resp *corev1.ClassifyResponse, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("classify: %v", err)
		return
	}
	if resp.GetError() != "" {
		t.Errorf("worker error: %s", resp.GetError())
		return
	}
	for _, h := range resp.GetHits() {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_CPF && h.GetCount() == 1 {
			return
		}
	}
	t.Errorf("expected a CPF hit, got %v", resp.GetHits())
}

// Many concurrent classifications across a pool all return the correct result —
// the acquire/release semaphore is race-free (run under -race) and each worker
// serves one request at a time.
func TestPoolConcurrentClassify(t *testing.T) {
	pool, err := privileged.StartPool(context.Background(), buildWorker(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := pool.Classify(context.Background(), cpfContentReq(fmt.Sprintf("r%d", i)))
			assertCPF(t, resp, err)
		}(i)
	}
	// Bound the wait: 40 calls on a size-4 pool only complete if workers are
	// RELEASED after each call; a broken release deadlocks, caught here rather than
	// hanging the suite.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("pool deadlocked — workers were not released back after Classify")
	}
}

// A size-1 pool is a valid degenerate case.
func TestPoolSizeOne(t *testing.T) {
	pool, err := privileged.StartPool(context.Background(), buildWorker(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	resp, err := pool.Classify(context.Background(), cpfContentReq("r1"))
	assertCPF(t, resp, err)
}

// Close is idempotent and closes the workers; a Classify after Close returns
// (the context path or a closed-worker error) rather than hanging.
func TestPoolCloseIsBounded(t *testing.T) {
	pool, err := privileged.StartPool(context.Background(), buildWorker(t), 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = pool.Close()
	_ = pool.Close() // idempotent

	// After Close the idle set is empty; a Classify must not hang — the acquire
	// select must honour a cancelled context. Bound it so a mutation that ignores
	// ctx fails cleanly instead of hanging.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { _, err := pool.Classify(ctx, cpfContentReq("r1")); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Classify on a closed/empty pool with a cancelled context should not succeed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Classify did not return on a cancelled context — acquire ignores ctx cancellation")
	}
}
