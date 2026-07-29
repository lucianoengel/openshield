//go:build linux

package execmon

import (
	"encoding/binary"
	"math"
	"testing"
)

// inotifyFrame builds one struct inotify_event with a declared name length that need not match name.
//
// The mismatch is the point: a frame whose declared length disagrees with what follows is precisely
// what the decoder has to survive, and it is not constructible through the real kernel.
func inotifyFrame(wd int32, mask, declaredLen uint32, name []byte) []byte {
	b := make([]byte, 16+len(name))
	binary.LittleEndian.PutUint32(b[0:4], uint32(wd))
	binary.LittleEndian.PutUint32(b[4:8], mask)
	binary.LittleEndian.PutUint32(b[8:12], 0) // cookie
	binary.LittleEndian.PutUint32(b[12:16], declaredLen)
	copy(b[16:], name)
	return b
}

// FuzzDecodeInotify drives the record walk that marks binaries appearing after startup.
//
// THIS IS THE ONE PLACE IN THE PRIVILEGED AGENT THAT PARSES A LENGTH SUPPLIED BY ANYTHING OTHER THAN A
// FIXED-WIDTH STRUCT FIELD, and the `name[]` it delimits is an ATTACKER-CREATED FILENAME — whoever can
// write into a watched directory chooses those bytes. Until this walk was extracted from the read loop
// it could not be tested at all: reaching it needed a real inotify descriptor and a real filesystem.
//
// EXTRACTING IT FOUND A DEFECT THAT FUZZING ON THIS ARCHITECTURE NEVER WOULD. The original arithmetic
// was `int(u32(...))`, and on a 32-bit platform `int` is 32 bits, so a declared length of 0xFFFFFFFF
// becomes -1, the bounds check reads `15 > n` and passes, and the slice panics with `[16:15]`. Verified
// by compiling the original arithmetic for GOARCH=386 and running it. The agent builds for linux/386
// and linux/arm today; on amd64 it is harmless, which is why nothing had noticed — and why a fuzzer
// running here would have reported it clean forever.
func FuzzDecodeInotify(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 15)) // one byte short of a header
	f.Add(inotifyFrame(1, 0x100, 8, []byte("cc\x00\x00\x00\x00\x00\x00")))
	f.Add(inotifyFrame(1, 0x100, 0, nil))                  // no name at all
	f.Add(inotifyFrame(1, 0, math.MaxUint32, []byte("x"))) // the 32-bit panic
	f.Add(inotifyFrame(1, 0, 64, []byte("short")))         // declared length overruns the buffer
	f.Add(inotifyFrame(1, 0, 4, []byte("nonul")))          // name with no terminator
	f.Add(append(inotifyFrame(1, 0, 4, []byte("a\x00\x00\x00")),
		inotifyFrame(2, 0, 4, []byte("b\x00\x00\x00"))...)) // two records: the walk, not one record

	f.Fuzz(func(t *testing.T, in []byte) {
		recs := decodeInotify(in)

		// EVERY RECORD MUST HAVE COST AT LEAST A HEADER. The walk has no remainder to check, so this is
		// the same progress property expressed over its output: more records than the buffer can hold at
		// sixteen bytes apiece means some iteration advanced by less than a header, which is the shape a
		// non-terminating walk would have had if the bound were not structural.
		if max := len(in) / 16; len(recs) > max {
			t.Fatalf("decodeInotify returned %d records from %d bytes, more than the %d a 16-byte header "+
				"permits — an iteration consumed less than one record", len(recs), len(in), max)
		}
		// AND NO NAME MAY EXCEED THE BUFFER. A name longer than its input is a read past the end that
		// happened not to fault.
		for i, r := range recs {
			if len(r.Name) > len(in) {
				t.Fatalf("record %d carries a %d-byte name from a %d-byte buffer", i, len(r.Name), len(in))
			}
		}
	})
}
