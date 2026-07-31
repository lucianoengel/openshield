package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// CORRELATION BACKFILL (SOAR-10).
//
// Correlation runs over a look-back window, on a clock. Alerts outside that window are never correlated —
// and the ones that matter most are exactly the ones that fell outside because correlation was NOT
// RUNNING: a leader outage, an interval left at zero, a deployment gap, a database that was down. Those
// alerts sit in the store forever, individually visible and never joined, and the incident that should
// have paged somebody simply does not exist. Nothing reports its absence, because nothing knows it was
// supposed to be there.
//
// Backfill runs the same rules over a historical range, stepping the window through it.
//
// A BACKFILLED INCIDENT IS NOT THE SAME THING AS A LIVE ONE, and the whole design follows from that:
//
//   - IT DOES NOT PAGE. A month of backfill would page the SOC for hundreds of incidents that are long
//     over, at which point the pager is muted and the next live incident is muted with it. The evidence
//     is written; the alarm is not rung for something nobody can respond to any more.
//   - IT IS EXCLUDED FROM RESPONSE METRICS. Its `created_at` is when the backfill ran, so its detection
//     latency would be the age of the alert and its time-to-acknowledge would start from a moment no
//     analyst could have acted on. Averaged in with real incidents, a single backfill would make the
//     fleet's measured response look arbitrarily good or arbitrarily bad depending on how far back it
//     reached.
//   - IT IS MARKED, so an operator reading one knows why its timestamps do not mean what they usually do.
//
// It is IDEMPOTENT by the same mechanism live correlation is: the partial-unique-on-open indexes make a
// re-run extend the existing incident rather than duplicate it. Running the same backfill twice is safe,
// which matters because the reason to run one at all is usually that nobody is sure what was missed.

// ErrBadRange is an unusable backfill range.
var ErrBadRange = errors.New("controlplane: the backfill range is empty or inverted")

// maxBackfillSteps bounds one backfill run.
//
// A bound is required rather than prudent. The range comes from an operator, the step from the rule's
// window, and "since 1970 with a one-minute window" is a plausible typo that would run for half a million
// steps against the database the live pipeline is using. Exceeding it is an ERROR rather than a silent
// truncation: a backfill that quietly covered the first thousand steps and stopped would report success
// over a range it did not cover, which is the same shape as the gap it was run to close.
const maxBackfillSteps = 5000

// BackfillResult is what one run covered — reported in full, because "how much of what I asked for
// actually happened" is the only question worth asking of a retrospective job.
type BackfillResult struct {
	Steps      int       `json:"steps"`
	Burst      int       `json:"burst_incidents"`
	CrossD     int       `json:"cross_domain_incidents"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
	StepWindow string    `json:"step_window"`
}

// Backfill re-runs BOTH correlation rules across a historical range, stepping by the rule's window.
//
// The step is the window itself, so every alert in the range is inside exactly one step's look-back and
// the same grouping the live loop would have produced is reproduced. A step SMALLER than the window would
// correlate overlapping sets and a step LARGER would leave gaps between them — the one case being a gap
// in a job whose entire purpose is closing gaps.
func (s *Server) Backfill(ctx context.Context, burst CorrelationRule, cross CrossDomainRule,
	from, to time.Time) (BackfillResult, error) {
	if !to.After(from) {
		return BackfillResult{}, fmt.Errorf("%w: %s → %s", ErrBadRange, from.Format(time.RFC3339),
			to.Format(time.RFC3339))
	}
	step := burst.Window
	if step <= 0 {
		step = time.Hour
	}
	if steps := int(to.Sub(from)/step) + 1; steps > maxBackfillSteps {
		return BackfillResult{}, fmt.Errorf(
			"%w: %s at a %s step is %d windows, over the %d limit — narrow the range or widen the "+
				"window rather than having this cover part of it and report success",
			ErrBadRange, to.Sub(from), step, steps, maxBackfillSteps)
	}

	res := BackfillResult{From: from, To: to, StepWindow: step.String()}
	// QUIET FOR THE WHOLE RUN, restored on the way out even if a step fails. Set around the loop rather
	// than per step so a failure part way through cannot leave the remaining live traffic silent.
	s.backfilling.Add(1)
	defer s.backfilling.Add(-1)

	for at := from.Add(step); ; at = at.Add(step) {
		if at.After(to) {
			at = to
		}
		n, err := s.MaterializeIncidents(ctx, burst, at)
		if err != nil {
			return res, fmt.Errorf("backfill at %s: %w", at.Format(time.RFC3339), err)
		}
		res.Burst += n
		m, err := s.MaterializeCrossDomainIncidents(ctx, cross, at)
		if err != nil {
			return res, fmt.Errorf("backfill (cross-domain) at %s: %w", at.Format(time.RFC3339), err)
		}
		res.CrossD += m
		res.Steps++
		if !at.Before(to) {
			break
		}
	}
	// THERE IS NO MARKING PASS. The flag is written by the INSERT itself, from the same quiet() signal
	// that suppresses paging, so an incident is marked exactly when the run that raised it was a
	// backfill.
	//
	// The first version DID sweep afterwards, and it was wrong in a way that mattered: scoped by the
	// backfill RANGE start rather than the run's wall clock, a backfill of the last three days
	// relabelled every incident raised LIVE in those three days — and since backfilled incidents are
	// excluded from the response metrics, that silently deleted real incidents from the fleet's
	// measured performance. Its own test caught it. Re-scoping to the wall clock would have fixed that
	// case and left a race with the live correlation loop; marking at insert has neither problem,
	// because the only code that knows an incident is retrospective is the code inserting it.
	return res, nil
}

// quiet reports whether a backfill is in progress, so notifyIncident stays silent.
func (s *Server) quiet() bool { return s.backfilling.Load() > 0 }

// backfillHandler serves POST /correlate/backfill?since=RFC3339&until=RFC3339.
func (s *Server) backfillHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	from, err := time.Parse(time.RFC3339, q.Get("since"))
	if err != nil {
		http.Error(w, "since must be RFC3339: "+err.Error(), http.StatusBadRequest)
		return
	}
	to := s.now()
	if v := q.Get("until"); v != "" {
		to, err = time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "until must be RFC3339: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	burst := CorrelationRule{Window: time.Hour, MinAlerts: 3}
	cross := CrossDomainRule{Window: time.Hour, MinDomains: 2}
	if v := q.Get("window"); v != "" {
		d, derr := time.ParseDuration(v)
		if derr != nil || d <= 0 {
			http.Error(w, "window must be a positive duration", http.StatusBadRequest)
			return
		}
		burst.Window, cross.Window = d, d
	}
	if n, ierr := intParam(q, "min_alerts", 3); ierr == nil {
		burst.MinAlerts = n
	} else {
		http.Error(w, "bad min_alerts: "+ierr.Error(), http.StatusBadRequest)
		return
	}
	if n, ierr := intParam(q, "min_domains", 2); ierr == nil {
		cross.MinDomains = n
	} else {
		http.Error(w, "bad min_domains: "+ierr.Error(), http.StatusBadRequest)
		return
	}

	res, err := s.Backfill(r.Context(), burst, cross, from, to)
	switch {
	case err == nil:
		writeJSON(w, res)
	case errors.Is(err, ErrBadRange):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		// The partial result is returned WITH the error status: a backfill that covered four hundred
		// steps and failed on the four hundred and first has done real work, and an operator needs to
		// know where to resume rather than being told only that something went wrong.
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]any{"error": err.Error(), "partial": res})
	}
}
