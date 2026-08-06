package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WHICH SETTINGS CAN TURN THE PRODUCT OFF, AND WHICH WAY (SEC-A).
//
// Every field's only bound used to be its Kind's parseability. `Validate` existed on Field and had no
// caller anywhere outside tests, so "is this a duration" was the whole check on values that decide
// whether anything is detected at all. At single-admin tier, over `POST /config`, with no four-eyes and
// no TTL, an operator — or whoever holds an operator's credential — could set:
//
//	OPENSHIELD_CORRELATE_INTERVAL=0s     no incidents are raised at all
//	OPENSHIELD_OVERDUE_THRESHOLD=8760h   a killed agent is never reported missing
//	OPENSHIELD_BEACON_ALLOWLIST=<c2>     the C2 destination is never reported
//	OPENSHIELD_FLEET_RETENTION=1h        evidence purged through a SANCTIONED delete path,
//	  + RETENTION_INTERVAL=1m            which the ledger's hash chain does not cover
//
// Each of those is a valid duration or a valid string. Each passes every check the system had.
//
// Two things are needed and they are different. A BOUND refuses a value outside the range in which the
// feature works — and a bound alone is not enough, because most of these attacks use values that are
// perfectly reasonable in isolation (a 24-hour retention is a legitimate choice; it is a suspicious one
// on the day an incident is opened). A DIRECTION makes "this change moves toward less detection"
// COMPUTABLE, so the write path can say so without a human having to know which way each knob points.
//
// The direction is the part that generalises. Whether a specific value is acceptable is the operator's
// call; whether a change reduced the deployment's ability to see is not a matter of opinion.

// Sensitivity classifies what a field controls and which way weakens it.
//
// Deliberately about DETECTION rather than about "security" in general. "Is this security-relevant" is a
// question people answer differently; "does raising this number mean the product sees less" has one
// answer per field, and whoever declares the field knows it.
type Sensitivity uint8

const (
	// NotSensitive: changing this does not reduce what the deployment can detect or retain. The zero
	// value, so a field that has never been considered is not silently claimed to be safe in either
	// direction — it is claimed to be irrelevant, which the guard test then forces someone to confirm.
	NotSensitive Sensitivity = iota

	// RaisingWeakens: a LARGER value detects less. Intervals between sweeps, thresholds a score must
	// exceed, windows of silence tolerated before an agent is called missing.
	RaisingWeakens

	// LoweringWeakens: a SMALLER value detects or retains less. Retention windows, minimum sample
	// counts, look-back windows.
	LoweringWeakens

	// AnyChangeWeakens: the value is not ordered, so any edit is worth surfacing. Allowlists, routing
	// tables, rule files — adding one entry to an allowlist is the whole attack, and no comparison of
	// two strings can tell an added C2 domain from an added CDN.
	AnyChangeWeakens
)

func (s Sensitivity) String() string {
	switch s {
	case RaisingWeakens:
		return "raising_weakens"
	case LoweringWeakens:
		return "lowering_weakens"
	case AnyChangeWeakens:
		return "any_change_weakens"
	default:
		return "not_sensitive"
	}
}

// Weakens reports whether moving this field from one value to another reduces what the deployment can
// detect or retain.
//
// Unparseable values answer false rather than erroring: this is consulted on a path that has already
// validated, and a nil-safe predicate that never fails is what lets the caller use it in a log line
// without a second error path. A value that does not parse cannot get this far.
func (f Field) Weakens(from, to string) bool {
	if f.Sensitivity == NotSensitive || from == to {
		return false
	}
	if f.Sensitivity == AnyChangeWeakens {
		return true
	}
	a, b, ok := f.compare(from, to)
	if !ok {
		return false
	}
	if f.Sensitivity == RaisingWeakens {
		return b > a
	}
	return b < a
}

// compare returns the two values as ordered floats.
//
// A DISABLING VALUE SORTS AS THE WEAKEST POSSIBLE, not as zero, and this is the case the whole
// classification exists for. `OPENSHIELD_CORRELATE_INTERVAL=0s` does not mean "correlate infinitely
// often"; its own description says zero disables it. Ordering it numerically would make turning
// correlation OFF read as the strongest possible setting — the attack scoring as a hardening.
func (f Field) compare(from, to string) (a, b float64, ok bool) {
	a, ok = f.magnitude(from)
	if !ok {
		return 0, 0, false
	}
	b, ok = f.magnitude(to)
	return a, b, ok
}

func (f Field) magnitude(raw string) (float64, bool) {
	switch f.Kind {
	case KindDuration:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0, false
		}
		if d == 0 && f.ZeroDisables {
			// The weakest end of whichever direction this field points.
			if f.Sensitivity == RaisingWeakens {
				return math_MaxFloat64, true
			}
			return -math_MaxFloat64, true
		}
		return float64(d), true
	case KindInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return 0, false
		}
		if n == 0 && f.ZeroDisables {
			if f.Sensitivity == RaisingWeakens {
				return math_MaxFloat64, true
			}
			return -math_MaxFloat64, true
		}
		return float64(n), true
	case KindUnitInterval, KindString:
		v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// math_MaxFloat64 avoids importing math for one constant in a package that is otherwise dependency-free
// by design; the config schema is read by every binary including the privileged agent.
const math_MaxFloat64 = 1.7976931348623157e+308

// Bound is an operational range, the check that enforces it, and the sentence explaining what a value
// outside it breaks — declared TOGETHER (SEC-A/D467).
//
// One declaration, because the alternative is two: a `func(string) error` the server enforces and a
// separate human-readable range a form renders. Those drift, and they drift silently in the direction
// that matters — a UI offering a range wider than the server accepts produces a value an operator types,
// submits, and has refused, with the form insisting it was fine.
//
// Why is not decoration either. It is the difference between a form that says "must be <= 6h" and one
// that says what a longer sweep means, and an operator given only the rule routes around it.
type Bound struct {
	// Range is how the constraint reads to a person: "1m–24h", ">= 24h", "<= 6h", ">= 3". Never empty
	// for a declared bound — a bound a UI cannot render is a bound an operator meets by trial and error.
	Range string
	// Why states the consequence of exceeding it.
	Why string
	// Check enforces it. Parseability is the Kind's job and is never re-reported here.
	Check func(raw string) error
}

// atLeast bounds a duration below.
func atLeast(min time.Duration, why string) *Bound {
	return &Bound{
		Range: ">= " + min.String(),
		Why:   why,
		Check: func(raw string) error {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return nil // parseability is the Kind's job; do not report it twice
			}
			if d != 0 && d < min {
				return fmt.Errorf("%s is below the %s minimum: %s", raw, min, why)
			}
			return nil
		},
	}
}

// retentionAtLeast bounds a RETENTION WINDOW below. It differs from atLeast in one place, and that place
// is the whole reason it exists: ZERO IS NOT "DISABLED" HERE, IT IS "DELETE EVERYTHING".
//
// atLeast lets 0 through because for an INTERVAL that is a documented off switch — OPENSHIELD_CORRELATE_INTERVAL=0s
// means "do not sweep". A retention WINDOW is subtracted from now() to make a cutoff, so 0 yields
// `WHERE <ts> < now()`, which matches every row that exists. So the one value a floor is there to refuse
// was the one value atLeast waved through, on OPENSHIELD_FLEET_RETENTION as well (found while adding the
// missing bound to the view audit, D483 — the field held up as the model had the same hole).
func retentionAtLeast(min time.Duration, why string) *Bound {
	return &Bound{
		Range: ">= " + min.String(),
		Why:   why,
		Check: func(raw string) error {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return nil // parseability is the Kind's job; do not report it twice
			}
			if d < min {
				return fmt.Errorf("%s is below the %s minimum: %s (a retention window of zero is not "+
					"'disabled' — it is a cutoff of now(), which matches every row in the table)", raw, min, why)
			}
			return nil
		},
	}
}

// atMost bounds a duration above.
func atMost(max time.Duration, why string) *Bound {
	return &Bound{
		Range: "<= " + max.String(),
		Why:   why,
		Check: func(raw string) error {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return nil
			}
			if d > max {
				return fmt.Errorf("%s is above the %s maximum: %s", raw, max, why)
			}
			return nil
		},
	}
}

// between bounds a duration on both sides.
func between(min, max time.Duration, why string) *Bound {
	lo, hi := atLeast(min, why), atMost(max, why)
	return &Bound{
		Range: min.String() + "–" + max.String(),
		Why:   why,
		Check: func(raw string) error {
			if err := lo.Check(raw); err != nil {
				return err
			}
			return hi.Check(raw)
		},
	}
}

// atLeastN bounds an integer below.
func atLeastN(min int, why string) *Bound {
	return &Bound{
		Range: fmt.Sprintf(">= %d", min),
		Why:   why,
		Check: func(raw string) error {
			n, err := strconv.Atoi(raw)
			if err != nil {
				return nil
			}
			if n < min {
				return fmt.Errorf("%d is below the minimum of %d: %s", n, min, why)
			}
			return nil
		},
	}
}
