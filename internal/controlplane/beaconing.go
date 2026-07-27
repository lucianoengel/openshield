package controlplane

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/lucianoengel/openshield/internal/analytics/beacon"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/retain"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// Beaconing detection over the fleet aggregate (NIPS-6).
//
// It reads network-flow events the platform already collects and looks for the one signal an implant
// cannot easily give up: a CHECK-IN RHYTHM. Nothing new is captured — the destination and the timestamp
// are already in the verified event, the same discipline that let SOAR-5 enrich from existing evidence.
//
// ONLY VERIFIED EVENTS (D44). Beaconing is derived entirely from timing, so letting unsigned telemetry
// contribute would let anyone able to publish it manufacture a beacon against a destination of their
// choosing — or bury a real one under fabricated contacts.
//
// THE BASE RATE IS THE HARD PART and it is handled by design rather than hoped away: legitimate software
// beacons constantly, so this raises a MEDIUM alert carrying its evidence (interval, count, regularity)
// and never enforces. An allowlist is configuration, because a detector whose output is mostly known-good
// gets muted, and a muted detector is worse than none.

// BeaconRule parameterizes the sweep.
type BeaconRule struct {
	Window    time.Duration
	Options   beacon.Options
	Allowlist []string
}

// DetectBeaconing sweeps the window and records an alert per suspected beacon.
//
// Grouped per SUBJECT: a rhythm is a property of one endpoint talking to one destination. Pooling the
// fleet's contacts to a shared destination would synthesize a rhythm nobody exhibits — a hundred hosts
// checking for updates hourly at random offsets would look like a perfect beacon.
func (s *Server) DetectBeaconing(ctx context.Context, rule BeaconRule, now time.Time) (int, error) {
	window := rule.Window
	if window <= 0 {
		window = 24 * time.Hour
	}
	opts := rule.Options
	if opts.MinContacts == 0 && opts.MinRegularity == 0 {
		opts = beacon.DefaultOptions()
	}
	opts.Allowlist = map[string]bool{}
	for _, d := range rule.Allowlist {
		if d = strings.TrimSpace(d); d != "" {
			opts.Allowlist[d] = true
		}
	}

	rows, err := s.pool.Query(ctx,
		`SELECT payload, received_at FROM fleet_telemetry
		  WHERE kind='event' AND verified AND received_at >= $1 ORDER BY received_at`,
		now.Add(-window))
	if err != nil {
		return 0, err
	}
	perSubject := map[string][]beacon.Contact{}
	for rows.Next() {
		var payload []byte
		var at time.Time
		if err := rows.Scan(&payload, &at); err != nil {
			rows.Close()
			return 0, err
		}
		var ev corev1.Event
		if proto.Unmarshal(payload, &ev) != nil || ev.GetKind() != corev1.EventKind_EVENT_KIND_NETWORK_FLOW {
			continue
		}
		subject := ev.GetSubject().GetPseudonymousId()
		dest := ev.GetNetwork().GetSniHost()
		if dest == "" {
			dest = ev.GetNetwork().GetDstIp()
		}
		if subject == "" || dest == "" {
			continue
		}
		// The EVENT's observation time, falling back to receipt: a rhythm measured by when we happened to
		// receive telemetry would be a rhythm of the transport, not of the endpoint.
		when := at
		if t := ev.GetObservedAt(); t.IsValid() {
			when = t.AsTime()
		}
		perSubject[subject] = append(perSubject[subject], beacon.Contact{At: when, Destination: dest})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	subjects := make([]string, 0, len(perSubject))
	for s := range perSubject {
		subjects = append(subjects, s)
	}
	sort.Strings(subjects) // deterministic alert order
	recorded := 0
	for _, subject := range subjects {
		for _, f := range beacon.Detect(perSubject[subject], opts) {
			// The dedup key is (subject, destination, interval-bucket): the same beacon re-detected on the
			// next sweep must not raise a second alert, while a beacon whose interval CHANGES is worth
			// knowing about — operators retune implants.
			key := fmt.Sprintf("beacon:%s:%s:%ds", subject, f.Destination, int(f.Interval.Seconds()))
			err := s.RecordUnifiedAlert(ctx, AlertRecord{
				Domain: "nips", SubjectKind: xdr.KindDevice, Subject: subject,
				// MEDIUM, deliberately: on a real network most beacons are legitimate, and a detector
				// that cries critical at NTP gets muted within a week.
				Severity: SeverityMedium,
				// The title is a closed-vocabulary label (D241) — the EVIDENCE goes in the annotation,
				// never the destination in the title, which would put an observable in an alert list.
				Title:      "network beaconing",
				DedupKey:   key,
				DetectedAt: f.Last,
			})
			if err != nil {
				continue // RecordUnifiedAlert counts its own failures
			}
			recorded++
		}
	}
	return recorded, nil
}

// BeaconFailures counts sweeps that errored — a silent detector is one nobody notices has stopped.
var BeaconFailures atomic.Int64

// RunBeaconLoop sweeps for beaconing on its OWN schedule.
//
// Its own loop rather than a passenger on the correlation tick, and the reason is not tidiness: beaconing
// needs a ~24h window where burst correlation uses ~1h. Sharing a tick would mean either re-scanning a
// day of telemetry every correlation interval (redundant work, repeatedly), or measuring rhythm over an
// hour (useless — an hourly beacon has one contact in it).
//
// Leader-only, like every other singleton sweep, and read PER TICK from providers so an operator can
// retune the window or the thresholds without restarting (PLAT-5b). A failing tick is counted and logged,
// never fatal.
func (s *Server) RunBeaconLoop(ctx context.Context, interval func() time.Duration,
	rule func() BeaconRule, log *slog.Logger) {
	retain.DynamicLoop(ctx, interval, func(c context.Context) {
		n, err := s.DetectBeaconing(c, rule(), s.now())
		if err != nil {
			BeaconFailures.Add(1)
			if log != nil {
				log.Error("beaconing sweep failed", slog.Any("err", err))
			}
			return
		}
		if n > 0 && log != nil {
			log.Info("beaconing sweep recorded findings", slog.Int("count", n))
		}
	})
}
