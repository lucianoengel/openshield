package notify

import (
	"context"
	"errors"
	"time"
)

// Retry (SIEM-8). Webhook delivery is single-shot: a transient failure — a 5xx from the
// receiver, a timeout, a refused connection during a deploy — dropped the alert entirely. The
// detection was recorded (D30), but the human was never paged, which is the whole point of
// notification. Retrying wraps any Notifier and re-attempts a TRANSIENT failure with bounded
// exponential backoff, so a momentary blip is survived.
//
// Delivery stays best-effort: after the last attempt the final error is returned for the caller
// to log. Retry widens the window in which a blip is survived; it does not make delivery
// guaranteed (a receiver down for the whole backoff window still misses the page — durable
// queued delivery would be a heavier, separate mechanism).

// permanentError marks a failure that retrying cannot fix — a 4xx client error, a notification
// that will not serialize — as opposed to a transient one (5xx, timeout, refused). Retrying
// gives up immediately on a permanent error rather than wasting the remaining attempts.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Permanent marks err as non-retryable. A nil err stays nil.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{err}
}

// isPermanent reports whether err, or anything it wraps, is permanent.
func isPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

const (
	defaultAttempts = 3
	defaultBase     = 200 * time.Millisecond
	maxBackoff      = 30 * time.Second // cap so a large attempt count cannot sleep unboundedly
)

// Retrying re-attempts a transient delivery failure of Inner with exponential backoff.
type Retrying struct {
	Inner       Notifier
	MaxAttempts int           // total tries including the first (min 1)
	BaseDelay   time.Duration // backoff before the 2nd try; doubles each retry, capped at maxBackoff
	// sleep is the backoff wait, a seam for tests; nil uses a real context-aware sleep.
	sleep func(ctx context.Context, d time.Duration) error
}

// NewRetrying wraps inner with retry. Non-positive parameters fall back to the defaults.
func NewRetrying(inner Notifier, maxAttempts int, baseDelay time.Duration) *Retrying {
	return &Retrying{Inner: inner, MaxAttempts: maxAttempts, BaseDelay: baseDelay}
}

// Notify attempts delivery, retrying a transient failure until it succeeds, the attempts are
// exhausted, the failure is permanent, or the context is cancelled.
func (r *Retrying) Notify(ctx context.Context, n Notification) error {
	attempts := r.MaxAttempts
	if attempts < 1 {
		attempts = defaultAttempts
	}
	base := r.BaseDelay
	if base <= 0 {
		base = defaultBase
	}
	sleep := r.sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Backoff before a retry: base, 2·base, 4·base, … capped. Cancellation during the
			// wait returns promptly rather than sleeping out the window.
			d := base << (i - 1)
			if d > maxBackoff || d <= 0 { // d<=0 guards the shift overflowing to a negative
				d = maxBackoff
			}
			if serr := sleep(ctx, d); serr != nil {
				return serr
			}
		}
		err = r.Inner.Notify(ctx, n)
		if err == nil {
			return nil
		}
		if isPermanent(err) {
			return err // retrying will not fix it
		}
	}
	return err // exhausted — best-effort, the caller logs
}

// sleepCtx waits d or returns early if ctx is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
