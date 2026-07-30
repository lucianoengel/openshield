package controlplane

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// A COMPROMISED ENDPOINT CONTROLS ITS OWN CLOCK. This measures what can be measured about that, and says
// plainly what cannot.
//
// Clock skew was one of four properties the enterprise gap assessment named as unproven. Checking it
// produced three findings, and the third is the one that matters most.
//
// # 1. LIVENESS WAS ALREADY IMMUNE
//
// The dead-man's-switch derives from `received_at`, the CONTROL PLANE's clock (SEC-3). An agent cannot make
// itself look alive, or look dead, by lying about the time. Deliberate, and it holds.
//
// # 2. BEACONING TRUSTS THE ENDPOINT'S CLOCK, AND HAS TO
//
// Beaconing detection measures the RHYTHM of outbound contacts using the event's own `observed_at`, for a
// reason recorded where it is used: "a rhythm measured by when we happened to receive telemetry would be a
// rhythm of the transport, not of the endpoint." That is correct — and it means an implant on a compromised
// host authors the very evidence the detector consults. It can beacon on a perfect interval and report
// jittered times for those contacts.
//
// # 3. AND THAT EVASION CANNOT BE CLOSED HERE. THE FIRST ATTEMPT AT THIS FILE TRIED, AND WAS WRONG.
//
// The obvious fix is to distrust timestamps that disagree with receipt time beyond a tolerance and fall
// back to receipt time for rhythm analysis. It destroys beaconing detection outright, and the reason is
// this product's own offline queue: an agent that spooled while disconnected (D40/D67) drains hours of
// telemetry whose `observed_at` is legitimately hours before `received_at`. Network delay does the same on
// a smaller scale. Written and run, it took beacon detections from 1 to 0 on the existing test.
//
// So: A TIMESTAMP IN THE PAST IS INDISTINGUISHABLE FROM LEGITIMATE LATENESS. An implant lying backwards
// looks exactly like an endpoint that was offline, and no threshold separates them, because the difference
// is not in the data. Closing it needs a time source the endpoint does not control — D64's "completeness
// needs an external anchor", applied to time — and that is a different and much larger piece of work.
//
// # WHAT IS ACTUALLY DECIDABLE, AND IS NOW CHECKED
//
// A timestamp in the FUTURE is unambiguous: an event cannot be observed after it was received. There is no
// benign explanation, so beyond a tolerance for ordinary drift it is reported and the event is measured by
// receipt time instead. That is a narrower claim than the first version made and it is one the data
// supports.
//
// It is also worth having on its own: a future-dated event sorts to the top of an incident timeline and
// can sit outside an analysis window entirely, so an endpoint that dates its contacts forward can push them
// out of the very sweep meant to catch them.

// DefaultSkewTolerance bounds how far into the FUTURE an agent's timestamp may sit before it stops being
// trusted.
//
// Two minutes rather than seconds: NTP-synced machines sit well inside it, a virtual machine resuming from
// suspend can briefly exceed it, and a bound tight enough to fire on ordinary drift produces an alert
// nobody reads. It is a plausibility check, not a synchronisation requirement.
//
// It deliberately does NOT bound the past — see the file comment. A past timestamp is what every spooled
// event legitimately has.
const DefaultSkewTolerance = 2 * time.Minute

// SkewTolerance reads the configured tolerance. A malformed or non-positive value falls back to the
// default: a typo must not silently become "no bound".
func SkewTolerance() time.Duration {
	if v := strings.TrimSpace(os.Getenv("OPENSHIELD_CLOCK_SKEW_TOLERANCE")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultSkewTolerance
}

// skewedEvents counts events dated implausibly far in the future.
var skewedEvents atomic.Int64

// SkewedEvents reports how many events arrived dated in the future beyond the tolerance. Non-zero means at
// least one endpoint's clock is ahead of this server's, or is being reported that way.
func SkewedEvents() int64 { return skewedEvents.Load() }

// skewWarned tracks agents already reported, so a persistently skewed endpoint produces one line rather
// than one per event — a warning that repeats per event is one people filter out.
var skewWarned sync.Map

// plausibleObservationTime returns the time to use for rhythm analysis, and whether the event's own
// timestamp was trusted.
//
// receivedAt is the control plane's own receipt time — the only independent reference available. ONLY THE
// FUTURE DIRECTION IS CHECKED: a timestamp before receipt is what every spooled or delayed event has, and
// treating that as suspicious destroys the analysis (see the file comment).
func plausibleObservationTime(ev *corev1.Event, receivedAt time.Time, tolerance time.Duration) (time.Time, bool) {
	t := ev.GetObservedAt()
	if !t.IsValid() {
		// Missing data, not a lying clock. Falls back silently — conflating the two would bury the signal
		// this exists to raise.
		return receivedAt, false
	}
	observed := t.AsTime()
	if observed.Sub(receivedAt) > tolerance {
		skewedEvents.Add(1)
		return receivedAt, false
	}
	return observed, true
}

// reportSkewedAgent names an endpoint dating its events in the future, once.
func reportSkewedAgent(agentID string, ahead time.Duration, tolerance time.Duration) {
	if agentID == "" {
		return
	}
	if _, seen := skewWarned.LoadOrStore(agentID, true); seen {
		return
	}
	fmt.Fprintf(os.Stderr, "openshield-server: agent %q dates its events %s in the FUTURE relative to this "+
		"server (tolerance %s) — an event cannot be observed after it was received, so this clock is wrong or "+
		"is being reported wrongly. Those events are measured by receipt time instead. Note the limit: a "+
		"timestamp in the PAST is indistinguishable from an event that was spooled while the agent was "+
		"offline, so backward skew is not detectable here.\n", agentID, ahead.Round(time.Second), tolerance)
}
