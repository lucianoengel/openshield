package clipboard

import (
	"sync"
	"sync/atomic"
)

// ContentStore holds the bytes for events whose content is out-of-band, keyed by event id, so the engine's
// classify stage can fetch them and classify in the SANDBOXED WORKER (D71/D29). It is how clipboard content
// reaches the classifier without ever touching an Event (D10).
//
// Two properties are load-bearing:
//
//   - It CHAINS. engine.SetContentResolver holds exactly ONE function, and this store's Resolve delegates to
//     whatever resolver was already installed when it misses. Overwriting would work today (nothing else
//     installs one) and would silently break the first time a second producer arrives — the SMTP body path
//     the seam was written for. A lost classification with no error is the worst kind of regression, so the
//     chaining behavior has its own test.
//   - It RELEASES. An entry is deleted when resolved, and the map is bounded. A producer that registered
//     content and never dropped it would grow with every copy the user makes, in a long-running process.
type ContentStore struct {
	// Next is consulted when this store has no entry for the event. nil = no chained resolver.
	Next func(eventID string) []byte
	// Max bounds retained entries. On overflow the oldest registration is dropped (see Put).
	Max int

	mu       sync.Mutex
	items    map[string][]byte
	order    []string
	consumed map[string]bool // ids already resolved once, bounded like `order`
	spent    []string

	// repeats counts a Resolve for an event id whose content was ALREADY consumed (DLP-2).
	//
	// It exists because the failure that motivated it was silent. Two producers ran the pipeline twice
	// over one job — the decider for its verdict, the observation loop because the event had also been
	// enqueued — and since this store releases on read, the second run classified NOTHING. For a print
	// job or a clipboard copy, whose whole content arrives out-of-band, an empty classification is a
	// clean result, not an error: the blind run was indistinguishable from a clean document, and when
	// it was the verdict, the job printed.
	//
	// A plain miss counter would be noise: the engine consults the resolver for every non-filesystem
	// event, and a DNS query legitimately has no content. A REPEAT is precise — it means something
	// asked for bytes another consumer already took, which is only ever a duplicate pipeline run.
	repeats atomic.Int64
}

// Repeats reports how many times content was requested for an event id that had already been
// resolved. Non-zero means one event is being processed by more than one consumer, and that at least
// one of them classified nothing while looking exactly like a clean result.
func (s *ContentStore) Repeats() int64 { return s.repeats.Load() }

// DefaultMaxEntries bounds pending content registrations. Content is normally resolved microseconds after
// it is registered (the producer emits the event immediately), so anything beyond a handful means the
// pipeline is not draining — and in that case dropping the oldest is better than growing without limit.
const DefaultMaxEntries = 64

// NewContentStore returns a store chaining to next (which may be nil).
func NewContentStore(next func(eventID string) []byte) *ContentStore {
	return &ContentStore{Next: next, Max: DefaultMaxEntries, items: map[string][]byte{}}
}

// Put registers content for an event id.
func (s *ContentStore) Put(eventID string, b []byte) {
	if eventID == "" || len(b) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = map[string][]byte{}
	}
	max := s.Max
	if max <= 0 {
		max = DefaultMaxEntries
	}
	if _, exists := s.items[eventID]; !exists {
		s.order = append(s.order, eventID)
	}
	s.items[eventID] = b
	// Drop the OLDEST unresolved registrations, not the newest: a newly copied item is the one about to be
	// classified, and discarding it in favour of a stale entry would lose the live detection.
	for len(s.order) > max {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.items, oldest)
	}
}

// Resolve returns the content for an event and RELEASES it, or delegates to the chained resolver.
func (s *ContentStore) Resolve(eventID string) []byte {
	s.mu.Lock()
	b, ok := s.items[eventID]
	if ok {
		delete(s.items, eventID)
		for i, id := range s.order {
			if id == eventID {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
		s.remember(eventID)
	} else if s.consumed[eventID] {
		s.repeats.Add(1)
	}
	next := s.Next
	s.mu.Unlock()
	if ok {
		return b
	}
	if next != nil {
		return next(eventID)
	}
	return nil
}

// Len reports retained entries (for tests and for an operator counter).
func (s *ContentStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// remember records that an id's content has been handed out, so a later request for it is
// recognisable as a duplicate rather than as an ordinary miss. Bounded by the same ceiling as pending
// registrations: this is a recent-history window for detecting a duplicate consumer, not a log.
//
// Caller holds s.mu.
func (s *ContentStore) remember(eventID string) {
	if s.consumed == nil {
		s.consumed = map[string]bool{}
	}
	max := s.Max
	if max <= 0 {
		max = DefaultMaxEntries
	}
	if !s.consumed[eventID] {
		s.consumed[eventID] = true
		s.spent = append(s.spent, eventID)
	}
	for len(s.spent) > max {
		delete(s.consumed, s.spent[0])
		s.spent = s.spent[1:]
	}
}
