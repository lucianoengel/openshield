// Package queue is the agent's durable store-and-forward spool (T-024).
//
// "Offline-capable" is a core principle (D1), and until this the agent→control-
// plane path had nowhere to put a payload when the control plane was down — a
// laptop that woke on a train lost every Event it produced. For a product whose
// only honest claim is a trail of what it saw, that silent loss is the failure
// the whole system exists to prevent (D31).
//
// The queue is durable (survives a crash and a reboot), in order (strict FIFO —
// an out-of-order audit trail is a broken one), and BOUNDED (an unbounded spool
// is a disk-exhaustion DoS). Overflow drops the oldest payload and fires a loud
// callback: the honest guarantee is "no SILENT loss", not "no loss".
package queue

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const msgSuffix = ".msg"

// Queue is a durable, bounded, FIFO spool of opaque records on disk.
type Queue struct {
	dir string
	max int
	// OnOverflow is called with the dropped record's sequence when a payload is
	// evicted to stay under the ceiling. The agent wires this to a high-severity
	// audit entry — a drop that is not recorded is exactly the silent loss this
	// package exists to prevent.
	onOverflow func(seq uint64)

	mu   sync.Mutex
	next uint64 // next sequence to assign
}

// Open prepares a spool directory, recovering the next sequence from whatever is
// already there so a restart resumes exactly where it left off.
func Open(dir string, max int, onOverflow func(seq uint64)) (*Queue, error) {
	if max <= 0 {
		return nil, fmt.Errorf("queue: max must be positive, got %d", max)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("queue: creating spool: %w", err)
	}
	q := &Queue{dir: dir, max: max, onOverflow: onOverflow}
	seqs, err := q.sequences()
	if err != nil {
		return nil, err
	}
	if len(seqs) > 0 {
		q.next = seqs[len(seqs)-1] + 1
	}
	return q, nil
}

func (q *Queue) path(seq uint64) string {
	return filepath.Join(q.dir, fmt.Sprintf("%020d%s", seq, msgSuffix))
}

// sequences returns the queued sequences in ascending order. A partial file (a
// crash mid-write left a .tmp) is ignored — only completed .msg files count,
// which is what makes a torn write unable to corrupt the queue.
func (q *Queue) sequences() ([]uint64, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, fmt.Errorf("queue: reading spool: %w", err)
	}
	var seqs []uint64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, msgSuffix) {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(name, msgSuffix), 10, 64)
		if err != nil {
			continue
		}
		seqs = append(seqs, n)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}

// Len reports how many records are queued.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	seqs, err := q.sequences()
	if err != nil {
		return 0
	}
	return len(seqs)
}

// Enqueue durably appends a record. If the queue is at its ceiling, the OLDEST
// record is dropped (and OnOverflow fired) BEFORE the new one is written — so the
// freshest activity, which an active investigation is most likely to need,
// survives. Dropping is loud, never silent.
func (q *Queue) Enqueue(rec []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	seqs, err := q.sequences()
	if err != nil {
		return err
	}
	// Evict oldest until there is room for one more.
	for len(seqs) >= q.max {
		oldest := seqs[0]
		if err := os.Remove(q.path(oldest)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("queue: evicting %d: %w", oldest, err)
		}
		if q.onOverflow != nil {
			q.onOverflow(oldest)
		}
		seqs = seqs[1:]
	}

	seq := q.next
	// Write to a temp file then rename: the rename is atomic, so a crash leaves
	// either a complete .msg or nothing — never a torn record the drain path
	// could choke on.
	tmp := q.path(seq) + ".tmp"
	if err := os.WriteFile(tmp, rec, 0o600); err != nil {
		return fmt.Errorf("queue: writing temp: %w", err)
	}
	if err := os.Rename(tmp, q.path(seq)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("queue: committing: %w", err)
	}
	q.next++
	return nil
}

// Drain delivers queued records in sequence order via fn, removing each on
// success. It STOPS at the first error, keeping that record and everything after
// it for a later Drain — a transient control-plane outage must not lose the tail.
// Returns the number delivered and the stopping error (nil if fully drained).
func (q *Queue) Drain(fn func([]byte) error) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	seqs, err := q.sequences()
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, seq := range seqs {
		rec, err := os.ReadFile(q.path(seq))
		if err != nil {
			return delivered, fmt.Errorf("queue: reading %d: %w", seq, err)
		}
		if err := fn(rec); err != nil {
			return delivered, err // keep this record and the rest
		}
		if err := os.Remove(q.path(seq)); err != nil && !os.IsNotExist(err) {
			return delivered, fmt.Errorf("queue: removing delivered %d: %w", seq, err)
		}
		delivered++
	}
	return delivered, nil
}
