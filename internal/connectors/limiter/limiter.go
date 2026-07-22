// Package limiter is a shared token-bucket rate limiter for the connector listeners (NIPS-7). A UDP
// listener that feeds the pipeline mints a ledger write per accepted datagram, so a spoofed-source
// flood would grow the audit ledger at wire speed with attacker-chosen content — a ledger-poisoning
// DoS. A GLOBAL token bucket (not per-source, which spoofing defeats) bounds the rate at which a
// listener admits datagrams, so the ledger-write rate is capped regardless of the flood.
package limiter

import (
	"sync"
	"time"
)

// Limiter is a token bucket: it admits up to Burst events immediately, then at RatePerSec sustained.
type Limiter struct {
	mu           sync.Mutex
	tokens       float64
	max          float64
	refillPerSec float64
	last         time.Time
	now          func() time.Time // injectable clock for deterministic tests
}

// New builds a limiter admitting `burst` events immediately and `ratePerSec` sustained. A
// non-positive burst clamps to 1 so the limiter always admits at least one event.
func New(ratePerSec, burst float64) *Limiter {
	if burst < 1 {
		burst = 1
	}
	l := &Limiter{tokens: burst, max: burst, refillPerSec: ratePerSec, now: time.Now}
	l.last = l.now()
	return l
}

// SetClock injects the clock (tests only).
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
	l.last = now()
}

// Allow reports whether one event may proceed, consuming a token if so. Refills lazily from the
// elapsed time since the last call, capped at Burst.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.tokens += now.Sub(l.last).Seconds() * l.refillPerSec
	if l.tokens > l.max {
		l.tokens = l.max
	}
	l.last = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}
