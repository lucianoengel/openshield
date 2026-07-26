package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Response metrics (SOAR-6): how long the platform takes to raise an incident, and how long humans take
// to acknowledge and resolve it.
//
// NO MIGRATION. Every timestamp this reads was already recorded, because SOAR-2 (D250) stored them for
// exactly this and made the lifecycle FORWARD-ONLY so they would stay meaningful — "a lifecycle that can
// move backwards makes MTTA/MTTR unmeasurable" was the reason given for the constraint. This is that
// constraint paying for itself: `closed` is terminal, so a closed incident's LAST transition IS its
// closure, and `transitioned_at` can be read as the resolution time without a dedicated column.
//
// THE THREE DURATIONS ARE KEPT APART ON PURPOSE. Merged into one "response time" they answer no question:
//
//	detection latency  created_at − first_seen        OUR lag (correlation interval, ingest)
//	time to acknowledge acknowledged_at − created_at   the ANALYST's
//	time to resolve     transitioned_at − created_at   the response PROCESS's (closed incidents only)
//
// Measuring MTTA from created_at rather than first_seen is the deliberate part: an analyst cannot
// acknowledge an incident that does not exist yet, so measuring from the first alert would make MTTA a
// function of OPENSHIELD_CORRELATE_INTERVAL. That lag is real and worth seeing — which is why it gets its
// own metric instead of being hidden inside someone else's.
//
// NOT AGGREGATED PER ANALYST, deliberately. The operator is on every row and grouping by them would be
// trivial. Attribution on an INCIDENT serves accountability for a specific decision; the same data rolled
// into a per-person score is a workforce-surveillance product, applied to the very people running the
// tool. That is what D20/L1's posture refuses, so it is refused here too.

// Duration is one measured population: how many contributed, how many could NOT, and the shape.
//
// Excluded is not decoration. MTTA covers only acknowledged incidents and MTTR only closed ones, and the
// selection is correlated with what is being measured — the incidents nobody got to are exactly the ones
// that would look worst. "MTTA 4 minutes" over 3 of 200 incidents reads as fleet performance and is not.
type Duration struct {
	Count    int     `json:"count"`
	Excluded int     `json:"excluded"`
	P50      float64 `json:"p50_seconds"`
	P90      float64 `json:"p90_seconds"`
	Mean     float64 `json:"mean_seconds"`
	Sum      float64 `json:"sum_seconds"`
}

// ResponseReport is the fleet-level answer. No operator appears anywhere in it.
type ResponseReport struct {
	DetectionLatency  Duration  `json:"detection_latency"`
	TimeToAcknowledge Duration  `json:"time_to_acknowledge"`
	TimeToResolve     Duration  `json:"time_to_resolve"`
	Incidents         int       `json:"incidents"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// ResponseMetrics computes the three durations in one pass over `incidents`.
//
// percentile_disc picks an actual observed value rather than interpolating between two — for a response
// time, "half the incidents were acknowledged within X" is a statement about a real incident, and an
// interpolated p50 is a number that never happened.
func (s *Server) ResponseMetrics(ctx context.Context) (*ResponseReport, error) {
	if s.pool == nil {
		// The counters half of /metrics needs no database and must keep serving without one. An
		// unconfigured server reporting "response metrics unavailable" is right; one that panics on a
		// scrape is an outage in the monitoring path.
		return nil, errors.New("controlplane: response metrics need a database")
	}
	const q = `
SELECT
  count(*)                                                                             AS incidents,
  -- detection latency: every incident has both timestamps, so nothing is excluded.
  count(*) FILTER (WHERE created_at >= first_seen)                                     AS det_n,
  count(*) FILTER (WHERE created_at <  first_seen)                                     AS det_excl,
  coalesce(sum(extract(epoch FROM created_at - first_seen))
           FILTER (WHERE created_at >= first_seen), 0)                                 AS det_sum,
  coalesce(percentile_disc(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM created_at - first_seen))
           FILTER (WHERE created_at >= first_seen), 0)                                 AS det_p50,
  coalesce(percentile_disc(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM created_at - first_seen))
           FILTER (WHERE created_at >= first_seen), 0)                                 AS det_p90,
  -- time to acknowledge: only acknowledged incidents contribute; the rest are EXCLUDED, and counted.
  count(*) FILTER (WHERE acknowledged_at IS NOT NULL)                                  AS ack_n,
  count(*) FILTER (WHERE acknowledged_at IS NULL)                                      AS ack_excl,
  coalesce(sum(extract(epoch FROM acknowledged_at - created_at))
           FILTER (WHERE acknowledged_at IS NOT NULL), 0)                              AS ack_sum,
  coalesce(percentile_disc(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM acknowledged_at - created_at))
           FILTER (WHERE acknowledged_at IS NOT NULL), 0)                              AS ack_p50,
  coalesce(percentile_disc(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM acknowledged_at - created_at))
           FILTER (WHERE acknowledged_at IS NOT NULL), 0)                              AS ack_p90,
  -- time to resolve: CLOSED incidents only. A contained-but-not-closed incident is not resolved, and
  -- treating it as such would encode a policy this code does not own, so it is excluded and counted.
  count(*) FILTER (WHERE state = 'closed' AND transitioned_at IS NOT NULL)             AS res_n,
  count(*) FILTER (WHERE NOT (state = 'closed' AND transitioned_at IS NOT NULL))       AS res_excl,
  coalesce(sum(extract(epoch FROM transitioned_at - created_at))
           FILTER (WHERE state = 'closed' AND transitioned_at IS NOT NULL), 0)         AS res_sum,
  coalesce(percentile_disc(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM transitioned_at - created_at))
           FILTER (WHERE state = 'closed' AND transitioned_at IS NOT NULL), 0)         AS res_p50,
  coalesce(percentile_disc(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM transitioned_at - created_at))
           FILTER (WHERE state = 'closed' AND transitioned_at IS NOT NULL), 0)         AS res_p90
FROM incidents`
	var r ResponseReport
	var d, a, x Duration
	if err := s.pool.QueryRow(ctx, q).Scan(&r.Incidents,
		&d.Count, &d.Excluded, &d.Sum, &d.P50, &d.P90,
		&a.Count, &a.Excluded, &a.Sum, &a.P50, &a.P90,
		&x.Count, &x.Excluded, &x.Sum, &x.P50, &x.P90); err != nil {
		return nil, err
	}
	for _, p := range []*Duration{&d, &a, &x} {
		if p.Count > 0 {
			p.Mean = p.Sum / float64(p.Count)
		}
	}
	r.DetectionLatency, r.TimeToAcknowledge, r.TimeToResolve = d, a, x
	r.GeneratedAt = s.now().UTC()
	return &r, nil
}

// responseBuckets are the cumulative histogram bounds, in seconds: a minute, five, fifteen, half an hour,
// an hour, four, twelve, a day, three days. Coarse on purpose — the same reasoning as the severity
// buckets (SIEM-6): an operator reasons in "minutes / an hour / overnight / nobody looked", not in a
// false-precision scale.
var responseBuckets = []float64{60, 300, 900, 1800, 3600, 4 * 3600, 12 * 3600, 24 * 3600, 3 * 24 * 3600}

// responseHistograms renders the three durations in the Prometheus histogram format.
//
// Hand-written, like the rest of PLAT-4's exposition (no client library, no supply-chain surface), which
// means nothing enforces bucket/sum/count consistency but a test.
func (s *Server) responseHistograms(ctx context.Context) (string, error) {
	rep, err := s.ResponseMetrics(ctx)
	if err != nil {
		return "", err
	}
	// The per-observation values are needed for bucket counts, so fetch them once per family.
	out := ""
	for _, fam := range []struct {
		name, help, where, expr string
		d                       Duration
	}{
		{"openshield_incident_detection_latency_seconds",
			"Seconds from an incident's first contributing alert to the incident being raised (the platform's own lag, not an analyst's).",
			"created_at >= first_seen", "extract(epoch FROM created_at - first_seen)", rep.DetectionLatency},
		{"openshield_incident_time_to_acknowledge_seconds",
			"Seconds from an incident being raised to a human acknowledging it. Acknowledged incidents only; see the _excluded gauge.",
			"acknowledged_at IS NOT NULL", "extract(epoch FROM acknowledged_at - created_at)", rep.TimeToAcknowledge},
		{"openshield_incident_time_to_resolve_seconds",
			"Seconds from an incident being raised to it being closed. Closed incidents only; see the _excluded gauge.",
			"state = 'closed' AND transitioned_at IS NOT NULL", "extract(epoch FROM transitioned_at - created_at)", rep.TimeToResolve},
	} {
		counts, err := s.bucketCounts(ctx, fam.where, fam.expr)
		if err != nil {
			return "", err
		}
		out += "# HELP " + fam.name + " " + fam.help + "\n"
		out += "# TYPE " + fam.name + " histogram\n"
		for i, b := range responseBuckets {
			out += sprintBucket(fam.name, b, counts[i])
		}
		out += sprintInfBucket(fam.name, fam.d.Count)
		out += sprintFloat(fam.name+"_sum", fam.d.Sum)
		out += sprintInt(fam.name+"_count", fam.d.Count)
		// The EXCLUDED population as its own series, so an alert on a flattering average can also see
		// how much of the fleet that average leaves out.
		excl := fam.name + "_excluded"
		out += "# HELP " + excl + " Incidents that could not contribute to this measurement.\n"
		out += "# TYPE " + excl + " gauge\n"
		out += sprintInt(excl, fam.d.Excluded)
	}
	return out, nil
}

// bucketCounts returns, for each bound, how many observations are <= it (cumulative, as Prometheus
// histograms require).
func (s *Server) bucketCounts(ctx context.Context, where, expr string) ([]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+expr+` FROM incidents WHERE `+where)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make([]int, len(responseBuckets))
	for rows.Next() {
		var v float64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		for i, b := range responseBuckets {
			if v <= b {
				counts[i]++
			}
		}
	}
	return counts, rows.Err()
}

// responseReportHandler serves GET /report/response — the analyst-readable form.
func (s *Server) responseReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rep, err := s.ResponseMetrics(ctx)
	if err != nil {
		http.Error(w, "report unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, rep)
}

// The exposition helpers. Prometheus wants a specific text shape and there is no client library here
// (PLAT-4 kept the endpoint dependency-free), so these exist to keep the formatting in one place rather
// than spread across format strings that could drift apart.
func sprintBucket(name string, le float64, n int) string {
	return fmt.Sprintf("%s_bucket{le=\"%g\"} %d\n", name, le, n)
}

func sprintInfBucket(name string, n int) string {
	return fmt.Sprintf("%s_bucket{le=\"+Inf\"} %d\n", name, n)
}

func sprintFloat(name string, v float64) string { return fmt.Sprintf("%s %g\n", name, v) }

func sprintInt(name string, v int) string { return fmt.Sprintf("%s %d\n", name, v) }
