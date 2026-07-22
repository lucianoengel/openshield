package notify

import (
	"context"
	"errors"
)

// Multi fans one Notification out to several sinks (SIEM-8): a deployer can page one
// system AND archive to another. It is BEST-EFFORT across sinks — every sink is
// attempted even if an earlier one fails, so a single broken sink cannot suppress
// delivery to the healthy ones.
//
// COMPOSITION: Multi is the OUTER wrapper; wrap each inner sink in Retrying, i.e.
// Multi{Sinks: []Notifier{Retrying(w1), Retrying(w2)}}. The reverse — Retrying(Multi) —
// would re-deliver to sinks that ALREADY succeeded on a retry, double-paging. With retry
// inside, a transient failure re-attempts only the sink that failed.
type Multi struct {
	Sinks []Notifier
}

// NewMulti fans out to the given sinks. A single sink is returned as-is (no fanout
// wrapper needed); zero sinks yields a Nop.
func NewMulti(sinks ...Notifier) Notifier {
	switch len(sinks) {
	case 0:
		return Nop{}
	case 1:
		return sinks[0]
	default:
		return &Multi{Sinks: sinks}
	}
}

// Notify delivers to every sink and aggregates the failures. It never returns early on a
// sink error — all sinks are attempted first. The aggregate is marked Permanent only when
// EVERY failing sink failed permanently: if even one failure is transient, retrying the
// aggregate could still make progress, so it must not be reported as permanent. An empty
// Multi is a no-op success.
func (m *Multi) Notify(ctx context.Context, n Notification) error {
	var errs []error
	allPermanent := true
	for _, s := range m.Sinks {
		if err := s.Notify(ctx, n); err != nil {
			errs = append(errs, err)
			if !isPermanent(err) {
				allPermanent = false
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	// Decide permanence at the AGGREGATE level (all failing sinks permanent), then flatten to a
	// message-only error. We must NOT return errors.Join(errs...) directly: it keeps each child in
	// the tree, and errors.As traverses into it — so a single permanent child would make isPermanent
	// report the whole (possibly mixed) aggregate permanent, and an outer retry would give up on the
	// still-transient sinks. Flattening to the joined message drops child identity (the caller only
	// logs the aggregate) while letting Multi own the classification.
	agg := errors.New(errors.Join(errs...).Error())
	if allPermanent {
		return Permanent(agg)
	}
	return agg
}
