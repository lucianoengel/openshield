package controlplane

// Alert severity (SIEM-6). A peer alert's risk_score is a continuous [0,1] signal; an operator
// triages in BUCKETS. Severity was originally a pure derived label; SIEM-6b/ADR-10 now STORES it as
// a first-class column (computed at write via this function) so a cross-domain detector without a
// risk_score can still write a severity and cross-host correlation is uniform. The trade-off: a later
// threshold change no longer re-buckets history for free (a re-bucket would need a backfill) — accepted
// per ADR-10. This function stays the single source of the mapping used at write time. It is the
// prioritization primitive: the actionable queue is the high/critical, unacknowledged alerts.
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
