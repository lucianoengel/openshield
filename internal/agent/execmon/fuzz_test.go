package execmon

import (
	"encoding/binary"
	"math"
	"testing"
)

// FUZZING THE PRIVILEGED AGENT'S DECODERS.
//
// `go list -deps ./cmd/openshield-agent` returns eight openshield packages, and this is one of them.
// Everything decoded here runs in a process holding CAP_SYS_ADMIN that answers BLOCKING permission
// events — which is what sets the severity, not the language. Go rules out the memory-corruption class
// outright; what remains is a panic, an unbounded allocation, or a spin, and in THIS process each of
// those stops every open of a watched file until the watchdog budget fires, with the gate failing open
// throughout. A host-wide availability event, not a lost feature.
//
// WHAT EACH TARGET ASSERTS, BEYOND NOT PANICKING. Absence of a panic is what the fuzzer gives for free;
// any target body at all earns it. The property that matters for a streaming decoder is PROGRESS: its
// caller loops on the remainder, so a decode reporting success without consuming input is an infinite
// loop in the privileged agent. Go surfaces that only through its own hang timeout — as a stuck worker
// rather than as a malformed frame, and only after ten seconds. Asserting it here turns a class of
// wedged host into an ordinary failure with the offending bytes attached.

// metaFrame builds one fanotify_event_metadata with the given declared event_len.
func metaFrame(eventLen uint32, mask uint64, pid int32) []byte {
	b := make([]byte, metaLen)
	binary.LittleEndian.PutUint32(b[0:4], eventLen)
	b[4] = 3 // FANOTIFY_METADATA_VERSION, plausible rather than meaningful
	binary.LittleEndian.PutUint16(b[6:8], uint16(metaLen))
	binary.LittleEndian.PutUint64(b[8:16], mask)
	binary.LittleEndian.PutUint32(b[16:20], math.MaxUint32) // fd
	binary.LittleEndian.PutUint32(b[20:24], uint32(pid))
	return b
}

// FuzzDecodeMeta drives the exec gate's fanotify metadata decoder.
//
// The bytes come from the KERNEL, read off the notify descriptor. That is a trusted producer in
// practice, so the interesting inputs are the ones a trusted producer would never write — a
// desynchronised stream, a short read, a length field the buffer does not support — because the
// decoder's own comment promises it survives them.
func FuzzDecodeMeta(f *testing.F) {
	// SEEDED STRUCTURALLY, not from nothing. A fuzzer starting at []byte{} spends its budget
	// rediscovering the header length; these hand the corpus the shapes that matter on the first run.
	f.Add([]byte{})
	f.Add(make([]byte, metaLen-1))                                       // one byte short of a header
	f.Add(metaFrame(metaLen, 0x08, 1234))                                // valid, exactly one record
	f.Add(metaFrame(0, 0, 0))                                            // NON-TERMINATION candidate: consumes nothing
	f.Add(metaFrame(metaLen-1, 0, 0))                                    // under-runs the header
	f.Add(metaFrame(math.MaxUint32, 0, 0))                               // over-runs any buffer
	f.Add(append(metaFrame(metaLen, 1, 1), metaFrame(metaLen, 2, 2)...)) // two records: the LOOP, not one decode

	f.Fuzz(func(t *testing.T, in []byte) {
		buf := in
		// Bounded, because the assertion below is what proves termination — the loop must not be what
		// discovers a violation, or a regression presents as a test that hangs.
		for i := 0; i < 4096; i++ {
			m, rest, ok := decodeMeta(buf)
			if !ok {
				return
			}
			if len(rest) >= len(buf) {
				t.Fatalf("decodeMeta reported success on %d bytes and returned %d — a decode that "+
					"consumes nothing is an infinite loop in the process holding CAP_SYS_ADMIN, and the "+
					"kernel is holding a process the whole time it spins (event_len=%d)",
					len(buf), len(rest), m.EventLen)
			}
			if m.EventLen < metaLen {
				t.Fatalf("decodeMeta accepted event_len=%d, below the %d-byte header", m.EventLen, metaLen)
			}
			buf = rest
		}
		t.Fatalf("decodeMeta produced more than 4096 records from %d bytes — each one consumed at least "+
			"%d bytes, so this cannot happen unless the remainder is growing", len(in), metaLen)
	})
}
