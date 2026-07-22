package controlplane

// Alert severity (SIEM-6). A peer alert's risk_score is a continuous [0,1] signal; an operator
// triages in BUCKETS. Severity is a pure, derived label over the risk — not stored, so it
// cannot drift out of sync with the score it summarizes, and a threshold change re-buckets
// history without a migration. It is the prioritization primitive: the actionable queue is the
// high/critical, unacknowledged alerts.
//
// The thresholds are deliberately coarse — four buckets an analyst can hold in their head, not
// a false-precision scale. They are inclusive lower bounds, so an alert exactly at a threshold
// takes the higher bucket (0.90 is critical, 0.75 is high).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"

	critFloor = 0.90
	highFloor = 0.75
	medFloor  = 0.50
)

// Severity maps a risk score to its triage bucket.
func Severity(risk float64) string {
	switch {
	case risk >= critFloor:
		return SeverityCritical
	case risk >= highFloor:
		return SeverityHigh
	case risk >= medFloor:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// severityFloor returns the minimum risk score for a severity label, so a "min severity" filter
// translates to a risk floor. ok is false for an unrecognized label (the caller ignores the
// constraint rather than guessing a floor).
func severityFloor(sev string) (float64, bool) {
	switch sev {
	case SeverityCritical:
		return critFloor, true
	case SeverityHigh:
		return highFloor, true
	case SeverityMedium:
		return medFloor, true
	case SeverityLow:
		return 0, true
	default:
		return 0, false
	}
}
