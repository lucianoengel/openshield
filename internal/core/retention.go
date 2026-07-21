package core

import "time"

// MaxAge returns how long an entry of this retention class may be kept before a
// purge tombstones it. A returned ok=false means the class is HELD — exempt from
// routine purge, for an entry under an open investigation, where erasing
// evidence would be the wrong default (and, under a legal hold, unlawful).
//
// Durations are constants now; configuration is a later concern. The values are
// deliberately conservative: routine telemetry is short-lived, ordinary
// decisions live a year, investigation entries are held until explicitly closed.
func (c RetentionClass) MaxAge() (d time.Duration, bounded bool) {
	switch c {
	case RetentionShort:
		return 30 * 24 * time.Hour, true
	case RetentionStandard, RetentionUnspecified:
		// Unspecified is treated as Standard rather than "keep forever": an
		// unset class must not become an accidental indefinite-retention hole.
		return 365 * 24 * time.Hour, true
	case RetentionInvestigation:
		return 0, false // held
	default:
		return 365 * 24 * time.Hour, true
	}
}

// Expired reports whether an entry of this class, appended at appendedAt, is past
// its retention age as of now. Held classes never expire.
func (c RetentionClass) Expired(appendedAt, now time.Time) bool {
	d, bounded := c.MaxAge()
	if !bounded {
		return false
	}
	return now.Sub(appendedAt) > d
}
