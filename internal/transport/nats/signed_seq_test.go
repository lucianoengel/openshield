package nats

import (
	"os"
	"path/filepath"
	"testing"
)

// 3.1 — the sequence is strictly monotonic ACROSS a restart: a new publisher
// built from the same seq file resumes with a sequence greater than any the
// previous instance used, so a restart never emits a replay (D66).
func TestSignedSeqMonotonicAcrossRestart(t *testing.T) {
	f := filepath.Join(t.TempDir(), "seq")
	store := NewFileSeqStore(f)

	p1, err := NewSignedPublisherWithSeq("agent", nil, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	var maxUsed uint64
	for i := 0; i < 250; i++ { // spans several reserveBlock boundaries
		s, err := p1.nextSeq()
		if err != nil {
			t.Fatal(err)
		}
		if s <= maxUsed {
			t.Fatalf("non-monotonic within a run: %d <= %d", s, maxUsed)
		}
		maxUsed = s
	}

	// Restart: a fresh publisher from the SAME store.
	p2, err := NewSignedPublisherWithSeq("agent", nil, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p2.nextSeq()
	if err != nil {
		t.Fatal(err)
	}
	if s <= maxUsed {
		t.Fatalf("after restart the next seq is %d <= last used %d — a REPLAY the server rejects", s, maxUsed)
	}
}

// 3.2 — a corrupt seq file fails LOUDLY; the publisher refuses to start rather
// than silently reset to 0 and reintroduce the false-replay bug.
func TestSeqStoreCorruptFailsLoud(t *testing.T) {
	f := filepath.Join(t.TempDir(), "seq")
	if err := os.WriteFile(f, []byte("xx"), 0o600); err != nil { // not 8 bytes
		t.Fatal(err)
	}
	if _, err := NewSignedPublisherWithSeq("agent", nil, nil, NewFileSeqStore(f)); err == nil {
		t.Fatal("a corrupt seq file did not fail loudly — a silent reset reintroduces the bug")
	}
}
