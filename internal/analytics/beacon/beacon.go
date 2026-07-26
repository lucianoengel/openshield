// Package beacon detects command-and-control BEACONING: repeated contact with one destination at
// suspiciously REGULAR intervals (NIPS-6).
//
// Beaconing is the signal that survives when everything else about an implant is unremarkable. The
// destination may be a fresh domain no feed lists, the payload may be encrypted, the volume may be
// trivial — but an implant that checks in has to check in, and the RHYTHM of that check-in is hard to hide
// without giving up responsiveness.
//
// THE HONEST PART, and it is not a footnote: legitimate software beacons constantly. NTP, update checks,
// telemetry, monitoring agents, mail polling and heartbeats are all textbook beacons, and on a real
// network they will outnumber the malicious ones by orders of magnitude. So this is deliberately built as
// a RANKED SIGNAL WITH ITS EVIDENCE, not a verdict:
//
//   - every result carries the interval, the sample count and the regularity score, so an analyst can
//     dismiss "every 3600s to the NTP pool" in one glance rather than investigating it;
//   - an ALLOWLIST is a first-class input rather than an afterthought, because a detector whose output is
//     90% known-good gets muted, and a muted detector is worse than none;
//   - nothing here enforces. It produces a finding for a human, which is the only defensible use of a
//     detector with this base rate.
package beacon

import (
	"math"
	"sort"
	"time"
)

// Contact is one observed connection: when, and to what.
type Contact struct {
	At          time.Time
	Destination string
}

// Finding is one suspected beacon, WITH the evidence that justifies it.
//
// The evidence fields are not decoration. A finding an analyst cannot dismiss quickly is a finding they
// will eventually ignore entirely, and this detector's base rate makes fast dismissal the difference
// between a useful signal and a muted one.
type Finding struct {
	Destination string
	Contacts    int
	// Interval is the MEDIAN gap. Median rather than mean because one long gap — a laptop that slept, a
	// link that dropped — would drag a mean far from the rhythm actually observed.
	Interval time.Duration
	// Regularity is 1 - (MAD / median), clamped to [0,1]: 1.0 is a perfect metronome. Built on the MEDIAN
	// ABSOLUTE DEVIATION rather than the standard deviation because a single outlier gap inflates a
	// standard deviation enough to hide a beacon, and hiding from this detector by dropping one check-in
	// should not be that easy.
	Regularity float64
	// Jitter is the observed spread as a fraction of the interval — the operator-facing complement of
	// Regularity, since C2 frameworks configure jitter as a percentage.
	Jitter float64
	First  time.Time
	Last   time.Time
}

// Options tune the detector. The defaults are deliberately conservative: this fires on regular traffic,
// and regular traffic is mostly legitimate.
type Options struct {
	// MinContacts is how many observations are required. Below about eight, "regular" is not a
	// measurement — three contacts give two intervals, and two intervals are always "regular".
	MinContacts int
	// MinRegularity is the score at or above which a destination is reported.
	MinRegularity float64
	// MinInterval discards very fast repetition: a burst of connections milliseconds apart is a transfer
	// or a retry storm, not a check-in rhythm.
	MinInterval time.Duration
	// Allowlist is destinations never reported. First-class rather than an afterthought — see the package
	// comment on why a detector that is mostly known-good gets muted.
	Allowlist map[string]bool
}

// DefaultOptions are the conservative starting point.
func DefaultOptions() Options {
	return Options{MinContacts: 8, MinRegularity: 0.85, MinInterval: 5 * time.Second}
}

// Detect finds beaconing destinations among one subject's contacts.
//
// Results are ordered most-regular first, so the ranking an analyst reads top-down is the ranking the
// detector is most confident about.
func Detect(contacts []Contact, o Options) []Finding {
	if o.MinContacts <= 0 {
		o.MinContacts = DefaultOptions().MinContacts
	}
	byDest := map[string][]time.Time{}
	for _, c := range contacts {
		if c.Destination == "" || o.Allowlist[c.Destination] {
			continue
		}
		byDest[c.Destination] = append(byDest[c.Destination], c.At)
	}
	var out []Finding
	for dest, times := range byDest {
		if len(times) < o.MinContacts {
			continue
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		gaps := make([]float64, 0, len(times)-1)
		for i := 1; i < len(times); i++ {
			gaps = append(gaps, times[i].Sub(times[i-1]).Seconds())
		}
		median := medianOf(gaps)
		if median <= 0 || time.Duration(median*float64(time.Second)) < o.MinInterval {
			continue
		}
		dev := make([]float64, len(gaps))
		for i, g := range gaps {
			dev[i] = math.Abs(g - median)
		}
		mad := medianOf(dev)
		regularity := 1 - (mad / median)
		if regularity < 0 {
			regularity = 0
		}
		if regularity > 1 {
			regularity = 1
		}
		if regularity < o.MinRegularity {
			continue
		}
		out = append(out, Finding{
			Destination: dest,
			Contacts:    len(times),
			Interval:    time.Duration(median * float64(time.Second)),
			Regularity:  regularity,
			Jitter:      mad / median,
			First:       times[0],
			Last:        times[len(times)-1],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Regularity != out[j].Regularity {
			return out[i].Regularity > out[j].Regularity
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

// medianOf returns the median of a copy, leaving the caller's slice alone — sorting a caller's data as a
// side effect of measuring it is the kind of surprise that shows up as a bug somewhere else.
func medianOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	mid := len(c) / 2
	if len(c)%2 == 1 {
		return c[mid]
	}
	return (c[mid-1] + c[mid]) / 2
}
