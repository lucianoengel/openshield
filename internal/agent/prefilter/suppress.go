package prefilter

import (
	"sync"
	"sync/atomic"
	"time"
)

// PathSuppressor decides whether a gated file-open may be handed to the ASYNCHRONOUS tier.
//
// # WHY THIS EXISTS: THE ASYNC TIER FEEDS ITSELF
//
// The inline gate decides from a bounded prefix, so the whole file has to be classified afterwards
// (D16). But the asynchronous classification OPENS the file, that open falls under the same fanotify
// mark, the gate must answer it, and answering submits asynchronously again — forever.
//
// This is not a lock cycle that a deadlock detector would find. It is a feedback loop, and its
// failure mode is not a failing test: the opener is blocked in an UNINTERRUPTIBLE permission window,
// so a design that recurses wedges the host.
//
// # WHY PATHS AND NOT PIDS
//
// The obvious break — "do not resubmit events our own workers caused" — needs to know which processes
// are ours, and the process that opens is not the one on the verdict socket: the SANDBOXED WORKER does
// the open. Covering it means tracking a process group, which is the PID-exemption design (rejected:
// a stale exemption is a SILENT bypass, while everything here fails toward a stall or a fail-open).
//
// A path needs none of that. Submitting for a path suppresses further submissions for that path; the
// classification's own open still gets a verdict, it is simply not resubmitted, so the loop terminates
// after one iteration.
//
// # THE TTL ALONE WOULD NOT BE ENOUGH
//
// A plain time-to-live starting at submission is a race the loop wins whenever the queue is slow: if
// the entry expires before the classification's open arrives, that open resubmits, and the cycle
// restarts every TTL forever. So an entry is PENDING from Admit until Done, and a pending entry does
// not expire — the suppression structurally covers the gap between submitting and the open it causes,
// however long the queue is. The TTL then governs only re-classification of an unchanged file.
//
// # BOUNDED, BECAUSE THE KEYS ARE ATTACKER-INFLUENCED
//
// Paths come from whatever the host opens, so an unbounded map here is a memory primitive in the
// process that must stay up for the gate to work at all. At the ceiling, Admit REFUSES rather than
// evicting a live entry: refusing costs a missed asynchronous classification, which is a detection
// gap and is counted; evicting a pending entry would re-arm the loop. Given the choice between a gap
// and a wedged host, this takes the gap and reports it.
type PathSuppressor struct {
	ttl  time.Duration
	hold time.Duration
	max  int
	now  func() time.Time

	mu   sync.Mutex
	seen map[string]suppressEntry

	suppressed atomic.Int64
	saturated  atomic.Int64
	abandoned  atomic.Int64
}

// suppressEntry is one path's state. until is zero while the classification is PENDING.
type suppressEntry struct {
	started time.Time
	until   time.Time
}

// Suppression defaults.
const (
	// DefaultSuppressTTL is how long a COMPLETED classification suppresses re-classification of the
	// same path. Short: it exists so a burst of opens of one file is classified once, not so a file is
	// classified once per epoch. The file has not changed within it.
	DefaultSuppressTTL = 30 * time.Second

	// DefaultSuppressHold caps a PENDING entry, so a classification that dies without reporting cannot
	// suppress its path for the life of the process. It is a leak valve, not the loop bound — the loop
	// bound is Done — so it is generously longer than any classification should take.
	DefaultSuppressHold = 10 * time.Minute

	// DefaultSuppressMax bounds the map. Reached only by thousands of distinct paths inside one TTL,
	// which is a host under a very different kind of load than this feature is for.
	DefaultSuppressMax = 4096
)

// NewPathSuppressor builds a suppressor. Non-positive arguments take the defaults above.
func NewPathSuppressor(ttl, hold time.Duration, max int) *PathSuppressor {
	if ttl <= 0 {
		ttl = DefaultSuppressTTL
	}
	if hold <= 0 {
		hold = DefaultSuppressHold
	}
	if max <= 0 {
		max = DefaultSuppressMax
	}
	return &PathSuppressor{ttl: ttl, hold: hold, max: max, now: time.Now, seen: map[string]suppressEntry{}}
}

// Admit reports whether path may be submitted to the asynchronous tier now, and records it as PENDING
// when it says yes.
//
// Every yes must be followed by exactly one Done (the classification ran) or Release (it never did).
// Without one of them the path stays suppressed until the hold expires.
func (s *PathSuppressor) Admit(path string) bool {
	if path == "" {
		return false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.seen[path]; ok {
		if s.live(e, now) {
			s.suppressed.Add(1)
			return false
		}
		// Expired. If it expired while still PENDING the classification never reported, which is worth
		// counting separately: it means work was submitted and its completion was lost.
		if e.until.IsZero() {
			s.abandoned.Add(1)
		}
		delete(s.seen, path)
	}

	if len(s.seen) >= s.max {
		s.sweep(now)
	}
	if len(s.seen) >= s.max {
		// Full of LIVE entries. Refusing is the safe direction; see the type doc.
		s.saturated.Add(1)
		return false
	}
	s.seen[path] = suppressEntry{started: now}
	return true
}

// Done records that the asynchronous classification for path finished. Only now does the TTL start —
// until this call the entry cannot expire, which is what makes the cycle terminate regardless of how
// long the classification queued.
func (s *PathSuppressor) Done(path string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.seen[path]; ok && e.until.IsZero() {
		e.until = now.Add(s.ttl)
		s.seen[path] = e
	}
}

// Release forgets path entirely, for a submission that was admitted but never ran — a full queue, a
// shutdown. Forgetting rather than starting the TTL is deliberate: nothing was classified, so the next
// open SHOULD submit. It cannot re-arm the loop, because no classification means no open of our own.
func (s *PathSuppressor) Release(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, path)
}

// Suppressed counts submissions declined because the path was already in flight or recently done —
// the ordinary case, including every one of the classifier's own opens.
func (s *PathSuppressor) Suppressed() int64 { return s.suppressed.Load() }

// Saturated counts submissions declined because the cache was full of live entries. Non-zero means
// files were gated and never fully classified, which is the detection gap this trades for the bound.
func (s *PathSuppressor) Saturated() int64 { return s.saturated.Load() }

// Abandoned counts pending entries that expired without a Done — a classification that was submitted
// and whose completion was never reported.
func (s *PathSuppressor) Abandoned() int64 { return s.abandoned.Load() }

// Len is the number of tracked paths, for tests that assert the bound holds.
func (s *PathSuppressor) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// live reports whether an entry still suppresses. A pending entry lives until the hold; a completed
// one until its TTL.
func (s *PathSuppressor) live(e suppressEntry, now time.Time) bool {
	if e.until.IsZero() {
		return now.Sub(e.started) < s.hold
	}
	return now.Before(e.until)
}

// sweep drops every entry that no longer suppresses. Called only at the ceiling, so the ordinary path
// stays O(1).
func (s *PathSuppressor) sweep(now time.Time) {
	for k, e := range s.seen {
		if !s.live(e, now) {
			if e.until.IsZero() {
				s.abandoned.Add(1)
			}
			delete(s.seen, k)
		}
	}
}
