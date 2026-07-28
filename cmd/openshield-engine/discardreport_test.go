package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDiscardsAreReportedOnlyWhenTheyMove.
//
// Both halves matter and the SILENT one matters more: a periodic line that fires unconditionally gets
// filtered, and a filtered warning is a silence with extra steps.
func TestDiscardsAreReportedOnlyWhenTheyMove(t *testing.T) {
	var n atomic.Int64
	buf := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reportDiscards(ctx, log, "test", 20*time.Millisecond,
		discardCounter{"dropped", n.Load})

	// 1. NOTHING DISCARDED — several intervals must pass in silence.
	time.Sleep(120 * time.Millisecond)
	if got := buf.String(); got != "" {
		t.Fatalf("a listener discarding nothing produced output:\n%s", got)
	}

	// 2. THE COUNTER MOVES — it must be reported, with the value.
	n.Store(7)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), "dropped=7") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "dropped=7") {
		t.Fatalf("a listener that started discarding was not reported:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "not in the ledger") {
		t.Errorf("the report does not say what the discard COST — that those messages are absent from "+
			"the pipeline and the evidence store:\n%s", buf.String())
	}

	// 3. AND IT STOPS once the counter stabilises, so a listener that discarded once does not warn
	// forever about a number that is no longer changing.
	buf.Reset()
	time.Sleep(120 * time.Millisecond)
	if got := buf.String(); got != "" {
		t.Errorf("a stable counter kept producing warnings, which is how a real signal gets filtered "+
			"out by an operator:\n%s", got)
	}
}

// lockedBuffer is a race-free sink for the reporter's goroutine.
//
// A bare bytes.Buffer here is a DATA RACE — slog writes it from the reporting goroutine while the test
// reads it — and `go test -race` in CI is what caught it, not the local run. Worth keeping the note:
// the local check and the tree-wide one are looking for different things, and a concurrent test that
// passes without -race has established nothing about concurrency.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}
