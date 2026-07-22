package controlplane

import "testing"

// SIEM-6: severity buckets a continuous risk into a triage label. The thresholds are inclusive
// lower bounds, so a score exactly on a boundary takes the HIGHER bucket, and just below it
// drops to the next — the boundaries are where a bug would hide, so they are what is tested.
func TestSeverityBuckets(t *testing.T) {
	cases := []struct {
		risk float64
		want string
	}{
		{1.0, SeverityCritical},
		{0.90, SeverityCritical}, // boundary: inclusive → critical
		{0.8999, SeverityHigh},   // just below → high
		{0.75, SeverityHigh},     // boundary → high
		{0.7499, SeverityMedium}, // just below → medium
		{0.50, SeverityMedium},   // boundary → medium
		{0.4999, SeverityLow},    // just below → low
		{0.0, SeverityLow},
	}
	for _, c := range cases {
		if got := Severity(c.risk); got != c.want {
			t.Errorf("Severity(%v) = %q, want %q", c.risk, got, c.want)
		}
	}
}

// severityFloor round-trips each label to its threshold and rejects an unknown label (so a
// min-severity filter ignores garbage rather than guessing a floor).
func TestSeverityFloor(t *testing.T) {
	for _, sev := range []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		floor, ok := severityFloor(sev)
		if !ok {
			t.Errorf("severityFloor(%q) not recognized", sev)
		}
		if Severity(floor) != sev && sev != SeverityLow {
			t.Errorf("severityFloor(%q)=%v does not map back to %q", sev, floor, sev)
		}
	}
	if _, ok := severityFloor("bogus"); ok {
		t.Error("severityFloor accepted an unknown label")
	}
}
