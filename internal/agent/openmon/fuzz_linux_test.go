//go:build linux

package openmon

import (
	"math"
	"testing"
)

// FuzzDecodeMeta drives the FILE-OPEN gate's fanotify metadata decoder.
//
// THE MOST CONSEQUENTIAL DECODER IN THE TREE, by what depends on it rather than by what it does. It is
// three lines of shift arithmetic, and it runs in the process that answers FAN_OPEN_PERM — so while it
// is panicking or spinning, every process opening a file in a watched directory is stopped in an
// UNINTERRUPTIBLE window until the watchdog budget elapses, and the gate fails open for all of them.
//
// A SECOND DECODER OF THE SAME KERNEL STRUCT. `execmon` has its own, using `encoding/binary`, and this
// one is hand-rolled shifts that skip the mask field entirely. Three decoders of
// `fanotify_event_metadata` exist in the tree (the third is in the unprivileged connector) and they do
// not agree. They are deliberately NOT unified by this change: fuzzing both is how one learns whether
// they behave identically, and merging them first would destroy that evidence.
func FuzzDecodeMeta(f *testing.F) {
	// frame builds one metadata record with the given declared event_len, using LITTLE-ENDIAN bytes
	// written by hand — the decoder under test is hand-rolled, and encoding a frame with the same
	// arithmetic it decodes with would agree with itself whatever either did.
	frame := func(eventLen uint32, pid uint32) []byte {
		b := make([]byte, metaLen)
		b[0] = byte(eventLen)
		b[1] = byte(eventLen >> 8)
		b[2] = byte(eventLen >> 16)
		b[3] = byte(eventLen >> 24)
		b[4] = 3 // version
		b[20] = byte(pid)
		b[21] = byte(pid >> 8)
		b[22] = byte(pid >> 16)
		b[23] = byte(pid >> 24)
		return b
	}

	f.Add([]byte{})
	f.Add(make([]byte, metaLen-1))                         // one byte short of a header
	f.Add(frame(metaLen, 4242))                            // valid, exactly one record
	f.Add(frame(0, 0))                                     // NON-TERMINATION candidate: consumes nothing
	f.Add(frame(metaLen-1, 0))                             // under-runs the header
	f.Add(frame(math.MaxUint32, 0))                        // over-runs any buffer
	f.Add(append(frame(metaLen, 1), frame(metaLen, 2)...)) // two records: the LOOP

	f.Fuzz(func(t *testing.T, in []byte) {
		buf := in
		for i := 0; i < 4096; i++ {
			m, rest, ok := decodeMeta(buf)
			if !ok {
				return
			}
			if len(rest) >= len(buf) {
				t.Fatalf("decodeMeta reported success on %d bytes and returned %d. This decoder feeds the "+
					"loop that answers FAN_OPEN_PERM, so a decode consuming nothing does not crash — it "+
					"stops answering, and every opener stays stopped in an uninterruptible window "+
					"(event_len=%d)", len(buf), len(rest), m.EventLen)
			}
			if m.EventLen < metaLen {
				t.Fatalf("decodeMeta accepted event_len=%d, below the %d-byte header", m.EventLen, metaLen)
			}
			buf = rest
		}
		t.Fatalf("decodeMeta produced more than 4096 records from %d bytes, each consuming at least %d — "+
			"impossible unless the remainder grows", len(in), metaLen)
	})
}
