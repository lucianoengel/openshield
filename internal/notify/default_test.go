package notify_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/lucianoengel/openshield/internal/notify"
)

// Nop is the DEFAULT notifier — notification is opt-in, and a deployer turns it on by configuring a sink.
// So this runs in every deployment that has not configured one, which is the common case.
//
// It must return nil. The caller logs and continues on a delivery error (D30: the alert is already
// recorded, delivery is additive), so a Nop that returned an error would make every unconfigured
// deployment log a delivery failure for every alert — noise that looks like a broken integration and
// trains operators to ignore the one line that later matters.
func TestTheDefaultNotifierDeliversNowhereAndSaysNothingWentWrong(t *testing.T) {
	var n notify.Notifier = notify.Nop{}
	for _, note := range []notify.Notification{
		{},
		{Kind: "decision", Severity: "critical", Detail: "a thing happened"},
	} {
		if err := n.Notify(context.Background(), note); err != nil {
			t.Fatalf("Nop.Notify returned %v, want nil", err)
		}
	}
}

// Permanent marks a failure retrying cannot fix. isPermanent finds it with errors.As, which the existing
// tests cover — but a caller that wants to know WHY needs to reach the cause THROUGH the wrapper, and that
// is Unwrap's job. Without it, `errors.Is(err, io.ErrUnexpectedEOF)` on a permanently-failed delivery is
// false, and the wrapper that was added to carry information has hidden it instead.
func TestAPermanentErrorStillExposesItsCause(t *testing.T) {
	cause := io.ErrUnexpectedEOF
	err := notify.Permanent(cause)

	if err == nil {
		t.Fatal("Permanent(non-nil) returned nil")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is could not see through Permanent to %v — a caller cannot tell WHY delivery "+
			"failed permanently, only that it did", cause)
	}
	// The message must survive too: it is what gets logged, and "delivery failed" without the cause is
	// the same dead end from the other direction.
	if got := err.Error(); got != cause.Error() {
		t.Fatalf("Error() = %q, want %q", got, cause.Error())
	}

	// Through an additional layer of wrapping, which is what a real call stack does.
	wrapped := fmt.Errorf("posting to the sink: %w", err)
	if !errors.Is(wrapped, cause) {
		t.Fatal("the cause is lost once the permanent error is itself wrapped")
	}

	// A custom error type must be recoverable with errors.As, not merely comparable with Is.
	var target *namedError
	if !errors.As(notify.Permanent(&namedError{"boom"}), &target) || target.name != "boom" {
		t.Fatal("errors.As could not extract the concrete cause through Permanent")
	}
}

func TestPermanentOfNilIsNil(t *testing.T) {
	// A nil error must stay nil, or every success path that pipes its error through Permanent starts
	// reporting a failure that did not happen.
	if err := notify.Permanent(nil); err != nil {
		t.Fatalf("Permanent(nil) = %v, want nil", err)
	}
}

type namedError struct{ name string }

func (e *namedError) Error() string { return e.name }
