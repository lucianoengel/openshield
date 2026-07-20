package core

import (
	"context"
	"time"
)

// AuditSink adapts a Ledger to the Dispatcher's OnOutcome callback.
//
// It exists so the mapping from "pipeline outcome" to "ledger entry" is one
// reviewable function rather than something each caller reimplements. Every
// terminal outcome becomes an entry — decisions, failures and timeouts alike.
// A timeout in particular MUST be recorded: it converts a Block into an Allow,
// and an operator who cannot tell "nothing sensitive happened" from "the
// classifier timed out" has no signal (D17).
type AuditSink struct {
	Ledger Ledger
	// Now is injectable so tests do not depend on wall-clock ordering.
	Now func() time.Time
}

func NewAuditSink(l Ledger) *AuditSink {
	return &AuditSink{Ledger: l, Now: time.Now}
}

// Record is the OnOutcome callback.
//
// It returns the append error unchanged. Nothing here retries, buffers or
// degrades to a log line: an entry that is dropped here is indistinguishable
// from an event that never occurred, which is precisely the failure the ledger
// exists to prevent. Offline durability is T-024's problem, and solving it
// badly here would hide the gap rather than close it.
func (a *AuditSink) Record(ctx context.Context, s *State, o Outcome) error {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}

	e := &Entry{
		AppendedAt: now().UTC(),
		Decision:   o.Decision,
		Retention:  RetentionStandard,
	}
	if o.Kind != OutcomeDecided {
		// Recorded as an outcome rather than a Decision. Leaving these fields
		// empty would make a timeout look like an ordinary allow with a
		// missing decision id.
		e.OutcomeKind = o.Kind.String()
		e.OutcomeStage = o.Stage
	}
	if s != nil {
		e.ContextVersion = s.ContextVersion()
	}
	if d := o.Decision; d != nil {
		e.ContextVersion = d.GetContextVersion()
	}
	return a.Ledger.Append(ctx, e)
}
