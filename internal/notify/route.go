package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"
)

// Notification routing (SOAR-9).
//
// Before this, every notification went to every sink: a `low` peer alert woke whoever held the pager, and
// a `critical` incident landed in the same chat channel as everything else. That is how an alerting system
// stops working while still appearing to run — people mute the pager, and then the one page that mattered
// is muted too.
//
// FIRST MATCH WINS, in declared order, like a firewall rule set. The acceptance case — "critical to the
// pager ONLY" — is not expressible any other way: with a union of all matching rules, a
// `min: critical → pager` rule and a `min: low → chat` rule BOTH match a critical notification, so the
// critical page would also go to chat and the exclusivity is lost. The cost is that order matters and a
// broad early rule shadows later ones; that is inherent to the semantic and is legible in a short,
// ordered, load-validated table.
//
// ROUTING MATCHES KIND AND SEVERITY ONLY. There is deliberately no subject or entity selector: a rule
// keyed on a subject would put a pseudonymous identifier (D23) into a table an operator reads and edits,
// and — worse — would let one person's alerts be routed somewhere nobody looks.

// Severity labels, ranked. This is the ROUTING vocabulary; the risk→label MAPPING stays in the control
// plane (SIEM-6's Severity function) and is deliberately not duplicated here. A second copy of the
// mapping is exactly the drift SOAR-5 refused when it made the IOC store and the inline engine share one
// matcher; a test asserts every control-plane severity constant ranks here, so the two cannot silently
// diverge.
var severityRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

// SeverityRank returns a severity's ordering, and false for a value outside the closed vocabulary.
func SeverityRank(s string) (int, bool) {
	r, ok := severityRank[strings.ToLower(strings.TrimSpace(s))]
	return r, ok
}

// Route is one rule: which kinds, at what minimum severity, go to which named sinks.
//
// An empty Kinds means "any kind" — not "no kind" — because that is how an operator writing only a
// severity floor reads it. An empty MinSeverity means "any severity", including a notification whose
// producer set none.
type Route struct {
	Kinds       []Kind   `json:"kinds,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
	Sinks       []string `json:"sinks"`
}

// matches reports whether this rule selects a notification. It reads ONLY kind and severity.
func (r Route) matches(n Notification) bool {
	if len(r.Kinds) > 0 {
		found := false
		for _, k := range r.Kinds {
			if k == n.Kind {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.MinSeverity == "" {
		return true
	}
	floor, ok := SeverityRank(r.MinSeverity)
	if !ok {
		return false // an unvalidated rule matches nothing rather than everything
	}
	got, ok := SeverityRank(n.Severity)
	if !ok {
		// A notification with no (or an unknown) severity cannot satisfy a severity floor. It falls
		// through to the unrouted path, which delivers everywhere and counts — visible, not dropped.
		return false
	}
	return got >= floor
}

// Router delivers a notification to the sinks its first matching rule names.
type Router struct {
	Sinks  map[string]Notifier
	Routes []Route

	// Unrouted counts notifications that matched NO rule and were therefore delivered everywhere. It is
	// the signal that the table has a hole; see Notify.
	Unrouted atomic.Int64
	// MissingSink counts rules naming a sink that is not configured. Load validation refuses those, so a
	// non-zero value means the sink map changed after load.
	MissingSink atomic.Int64
}

// Notify routes and delivers.
//
// AN UNMATCHED NOTIFICATION GOES TO EVERY SINK, and is counted. Dropping it, or sending it to a "default"
// sink, both fail the same way: a table with a gap silently stops delivering exactly the notifications
// that fit no rule, and those are disproportionately likely to be the novel ones. Over-notifying is
// recoverable and the counter makes the hole visible; silence is neither. Same shape as the watchdog
// (D17) and the exec gate: degrade toward doing MORE, and say so.
//
// Delivery preserves the fanout guarantee — every selected sink is attempted even if an earlier one
// failed, and failures aggregate.
func (r *Router) Notify(ctx context.Context, n Notification) error {
	for _, rule := range r.Routes {
		if !rule.matches(n) {
			continue
		}
		// FIRST MATCH WINS: return whatever this rule's sinks produce, without consulting later rules.
		return r.deliver(ctx, n, rule.Sinks)
	}
	r.Unrouted.Add(1)
	return r.deliver(ctx, n, r.sinkNames())
}

func (r *Router) deliver(ctx context.Context, n Notification, names []string) error {
	var errs []error
	allPermanent := true
	delivered := 0
	for _, name := range names {
		sink, ok := r.Sinks[name]
		if !ok {
			// A rule naming an unconfigured sink must not swallow the notification: the remaining sinks
			// are still attempted and the mismatch is counted and reported.
			r.MissingSink.Add(1)
			errs = append(errs, fmt.Errorf("notify: route names unconfigured sink %q", name))
			allPermanent = false
			continue
		}
		delivered++
		if err := sink.Notify(ctx, n); err != nil {
			errs = append(errs, err)
			if !isPermanent(err) {
				allPermanent = false
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	agg := errors.New(errors.Join(errs...).Error())
	if allPermanent && delivered > 0 {
		return Permanent(agg)
	}
	return agg
}

// sinkNames is the full sink set, in a stable order so the unrouted fan-out is deterministic.
func (r *Router) sinkNames() []string {
	out := make([]string, 0, len(r.Sinks))
	for name := range r.Sinks {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ErrBadRoute is a structurally invalid routing table.
var ErrBadRoute = errors.New("notify: invalid routing table")

// LoadRoutes parses and VALIDATES an operator routing table (a JSON array) against the configured sink
// names.
//
// Validation happens at LOAD because a routing mistake discovered at delivery time is discovered by an
// alert not arriving — which is precisely the failure mode this ticket exists to remove.
func LoadRoutes(r io.Reader, sinkNames []string) ([]Route, error) {
	var routes []Route
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&routes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRoute, err)
	}
	known := make(map[string]bool, len(sinkNames))
	for _, s := range sinkNames {
		known[s] = true
	}
	for i, rt := range routes {
		if len(rt.Sinks) == 0 {
			// A rule with no sinks would silently discard everything it matched — the exact failure the
			// unrouted fail-open exists to prevent, reintroduced through configuration.
			return nil, fmt.Errorf("%w: rule %d selects no sinks", ErrBadRoute, i)
		}
		if rt.MinSeverity != "" {
			if _, ok := SeverityRank(rt.MinSeverity); !ok {
				return nil, fmt.Errorf("%w: rule %d: %q is not a severity", ErrBadRoute, i, rt.MinSeverity)
			}
		}
		for _, k := range rt.Kinds {
			if !knownKind(k) {
				return nil, fmt.Errorf("%w: rule %d: %q is not a notification kind", ErrBadRoute, i, k)
			}
		}
		for _, s := range rt.Sinks {
			if !known[s] {
				return nil, fmt.Errorf("%w: rule %d names sink %q, which is not configured", ErrBadRoute, i, s)
			}
		}
	}
	return routes, nil
}

// knownKind keeps the routable vocabulary closed: a typo'd kind would otherwise create a rule that never
// matches, i.e. a silent hole in the table.
func knownKind(k Kind) bool {
	switch k {
	case KindPeerAlert, KindAgentOverdue, KindIncident, KindApprovalPending:
		return true
	default:
		return false
	}
}
