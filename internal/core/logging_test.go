package core_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// TestErrorCategory pins the taxonomy: each sentinel, WRAPPED with context,
// categorises by identity (errors.Is), not by string. An unknown error → unknown.
func TestErrorCategory(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "ok"},
		{fmt.Errorf("ctx: %w", core.ErrNotRecorded), "not_recorded"},
		{fmt.Errorf("ctx: %w", core.ErrReentry), "reentry"},
		{fmt.Errorf("stage %q: %w", "x", core.ErrNoDecision), "no_decision"},
		{fmt.Errorf("%w: boom", core.ErrStageFailed), "stage_failed"},
		{fmt.Errorf("wrap: %w", context.DeadlineExceeded), "timeout"},
		{fmt.Errorf("wrap: %w", core.ErrUnreachable), "unreachable"},
		{fmt.Errorf("wrap: %w", core.ErrLedgerUnavailable), "ledger_unavailable"},
		{errors.New("some other error"), "unknown"},
	}
	for _, c := range cases {
		if got := core.Category(c.err); got != c.want {
			t.Errorf("Category(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), &buf
}

type boomStage struct{ err error }

func (boomStage) Name() string { return "boom" }
func (b boomStage) Run(context.Context, *core.State) (core.Outcome, error) {
	return core.Outcome{}, b.err
}

// A failing stage emits a log with the correlation id and category=stage_failed.
func TestFailureIsLogged(t *testing.T) {
	logger, buf := captureLogger()
	var r core.Registry
	r.Register(boomStage{errors.New("classifier exploded")})
	d := core.NewDispatcher(&r, time.Second)
	d.Logger = logger

	_, err := d.Dispatch(context.Background(), &corev1.Event{EventId: "evt-42"})
	if !errors.Is(err, core.ErrStageFailed) {
		t.Fatalf("err = %v, want ErrStageFailed", err)
	}
	out := buf.String()
	if !strings.Contains(out, "event_id=evt-42") {
		t.Errorf("log missing correlation id:\n%s", out)
	}
	if !strings.Contains(out, "category=stage_failed") {
		t.Errorf("log missing category=stage_failed:\n%s", out)
	}
}

type hangStage struct{}

func (hangStage) Name() string { return "hang" }
func (hangStage) Run(ctx context.Context, _ *core.State) (core.Outcome, error) {
	<-ctx.Done()
	return core.Outcome{}, ctx.Err()
}

// A timeout logs category=timeout at warn+; a not-recorded append logs
// category=not_recorded.
func TestTimeoutAndNotRecordedLogged(t *testing.T) {
	// Timeout.
	logger, buf := captureLogger()
	var r core.Registry
	r.Register(hangStage{})
	d := core.NewDispatcher(&r, 30*time.Millisecond)
	d.Logger = logger
	_, _ = d.Dispatch(context.Background(), &corev1.Event{EventId: "evt-t"})
	out := buf.String()
	if !strings.Contains(out, "category=timeout") {
		t.Errorf("timeout not logged with category=timeout:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("timeout not logged at warn+ (a timeout is a Block→Allow, D17):\n%s", out)
	}

	// Not-recorded: OnOutcome returns an error.
	logger2, buf2 := captureLogger()
	var r2 core.Registry
	r2.Register(decideStage("policy", testDecision()))
	d2 := core.NewDispatcher(&r2, time.Second)
	d2.Logger = logger2
	d2.OnOutcome = func(context.Context, *core.State, core.Outcome) error {
		return errors.New("ledger down")
	}
	_, err := d2.Dispatch(context.Background(), testEvent())
	if !errors.Is(err, core.ErrNotRecorded) {
		t.Fatalf("err = %v, want ErrNotRecorded", err)
	}
	if !strings.Contains(buf2.String(), "category=not_recorded") {
		t.Errorf("not-recorded append not logged:\n%s", buf2.String())
	}
}

type markerStage struct{}

func (markerStage) Name() string { return "marker" }
func (markerStage) Run(_ context.Context, s *core.State) (core.Outcome, error) {
	// Put a distinctive content marker on the decision reason — content that
	// must NOT reach a log.
	return core.Decided(&corev1.Decision{
		DecisionId: "d1", EventId: s.Event.GetEventId(),
		Action: corev1.Action_ACTION_ALERT, Reason: "SECRET-CONTENT-MARKER-9Z",
	}), nil
}

// A log is a wire (D10): the dispatcher's outcome logs carry ids and categories,
// never content.
func TestLogsCarryNoContent(t *testing.T) {
	logger, buf := captureLogger()
	var r core.Registry
	r.Register(markerStage{})
	d := core.NewDispatcher(&r, time.Second)
	d.Logger = logger
	if _, err := d.Dispatch(context.Background(), &corev1.Event{EventId: "evt-c"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "SECRET-CONTENT-MARKER-9Z") {
		t.Errorf("content marker leaked into the log — a log is a wire (D10):\n%s", buf.String())
	}
}
