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

type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// A GATEWAY THAT IS NOT BEING PROBED MUST SAY NOTHING. An unconditional periodic line gets filtered, and
// then the one that matters arrives inside a stream nobody reads (D348).
func TestAQuietGatewayReportsNothing(t *testing.T) {
	var risk atomic.Int64
	out := &safeBuf{}
	log := slog.New(slog.NewTextHandler(out, nil))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() { defer close(done); reportRejections(ctx, log, 20*time.Millisecond, rejectionCounter{"risk_rejected", risk.Load}) }()
	time.Sleep(120 * time.Millisecond)
	cancel()
	<-done

	if strings.Contains(out.String(), "SIGNED-CHANNEL INPUT REJECTED") {
		t.Fatalf("a gateway rejecting nothing produced a warning:\n%s", out.String())
	}
}

// A rising rejection count on a signed channel is somebody presenting forged material. It is the signal.
func TestARejectionIsReportedAndNamesItsChannel(t *testing.T) {
	var risk, posture atomic.Int64
	out := &safeBuf{}
	log := slog.New(slog.NewTextHandler(out, nil))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		reportRejections(ctx, log, 20*time.Millisecond,
			rejectionCounter{"risk_rejected", risk.Load},
			rejectionCounter{"posture_rejected", posture.Load})
	}()
	time.Sleep(40 * time.Millisecond)
	risk.Add(3)
	time.Sleep(120 * time.Millisecond)
	cancel()
	<-done

	got := out.String()
	if !strings.Contains(got, "SIGNED-CHANNEL INPUT REJECTED") {
		t.Fatalf("forged risk updates produced no report:\n%s", got)
	}
	if !strings.Contains(got, "risk_rejected=3") {
		t.Fatalf("the report does not name the channel or its count:\n%s", got)
	}
	// A channel at zero is omitted rather than printed as noise.
	if strings.Contains(got, "posture_rejected") {
		t.Errorf("a channel that rejected nothing was included:\n%s", got)
	}
}

// Once the flood stops the reporter goes quiet, or a single probe becomes a permanent warning and the next
// one is invisible inside it.
func TestItGoesQuietWhenTheRejectionsStop(t *testing.T) {
	var risk atomic.Int64
	out := &safeBuf{}
	log := slog.New(slog.NewTextHandler(out, nil))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() { defer close(done); reportRejections(ctx, log, 20*time.Millisecond, rejectionCounter{"risk_rejected", risk.Load}) }()
	risk.Add(1)
	time.Sleep(100 * time.Millisecond)
	first := strings.Count(out.String(), "SIGNED-CHANNEL INPUT REJECTED")
	if first == 0 {
		t.Fatal("the rejection was never reported")
	}
	time.Sleep(150 * time.Millisecond) // nothing moves
	cancel()
	<-done

	if got := strings.Count(out.String(), "SIGNED-CHANNEL INPUT REJECTED"); got != first {
		t.Fatalf("it kept warning after the rejections stopped (%d -> %d)", first, got)
	}
}

// No configured channels means nothing to report, and must not spin a goroutine that logs forever.
func TestNoCountersReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		reportRejections(context.Background(), slog.New(slog.NewTextHandler(&safeBuf{}, nil)), time.Millisecond)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reportRejections with no counters did not return")
	}
}
