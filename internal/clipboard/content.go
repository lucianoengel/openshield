package clipboard

import "sync"

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

	mu    sync.Mutex
	items map[string][]byte
	order []string
}

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
