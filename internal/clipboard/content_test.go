package clipboard_test

import (
	"strconv"
	"testing"

	"github.com/lucianoengel/openshield/internal/clipboard"
)

// DLP-2: a request for content that was ALREADY resolved is counted, because that is the only signal
// a duplicate pipeline run leaves behind.
//
// The store releases on read, so the second consumer classifies nothing — and for a print job or a
// clipboard copy, whose whole content arrives out-of-band, an empty classification is a CLEAN result
// rather than an error. The blind run is indistinguishable from a clean document, which is exactly
// how one job being processed twice went unnoticed while a verdict path silently allowed.
//
// A plain miss counter would be noise: the engine consults the resolver for every non-filesystem
// event, and a DNS query legitimately has none. A REPEAT is only ever a duplicate consumer.
//
// Mutation: drop the repeats increment → the count stays 0 → this FAILS.
func TestARepeatedResolveIsCountedSoADuplicateConsumerIsNotSilent(t *testing.T) {
	s := clipboard.NewContentStore(nil)
	s.Put("e1", []byte("secret"))

	if got := string(s.Resolve("e1")); got != "secret" {
		t.Fatalf("first resolve = %q, want the content", got)
	}
	if s.Repeats() != 0 {
		t.Fatalf("Repeats() = %d after ONE resolve, want 0", s.Repeats())
	}

	// The second consumer: same id, no content left.
	if b := s.Resolve("e1"); len(b) > 0 {
		t.Fatalf("second resolve returned %d bytes — the store must release on read", len(b))
	}
	if s.Repeats() != 1 {
		t.Fatalf("Repeats() = %d, want 1 — a duplicate pipeline run leaves no other trace: the "+
			"blind run classifies nothing and looks exactly like a clean document", s.Repeats())
	}

	// AN ORDINARY MISS IS NOT A REPEAT. The engine asks the resolver for every non-filesystem event,
	// and a DNS query has no content by nature. Counting those would bury the real signal.
	for _, id := range []string{"never-registered", "dns-42", ""} {
		if b := s.Resolve(id); len(b) > 0 {
			t.Fatalf("resolve(%q) returned content", id)
		}
	}
	if s.Repeats() != 1 {
		t.Errorf("Repeats() = %d after three ordinary misses, want still 1 — an event that never had "+
			"content is not a duplicate consumer", s.Repeats())
	}
}

// The repeat window is bounded: it is a recent-history check for a duplicate consumer, not a log that
// grows for the life of the process.
func TestTheRepeatWindowIsBounded(t *testing.T) {
	s := clipboard.NewContentStore(nil)
	s.Max = 4
	for i := 0; i < 20; i++ {
		id := "e" + strconv.Itoa(i)
		s.Put(id, []byte("x"))
		s.Resolve(id)
	}
	// The oldest ids have aged out of the window, so re-resolving them is an ordinary miss.
	s.Resolve("e0")
	if s.Repeats() != 0 {
		t.Errorf("Repeats() = %d for an id aged out of the window, want 0", s.Repeats())
	}
	// The most recent is still remembered.
	s.Resolve("e19")
	if s.Repeats() != 1 {
		t.Errorf("Repeats() = %d for a recently consumed id, want 1", s.Repeats())
	}
}
