package ipc_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/ipc"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// THE ONE FRAMING DECODER IN THE AGENT WITHOUT A FUZZER, and it sits on the most sensitive boundary in the
// product.
//
// execipc, openipc, openmon and execmon all fuzz their decoders. This package's framing did not, and it is
// the one the package comment describes as "the boundary between a process holding CAP_SYS_ADMIN and one
// that touches attacker-controlled files" — the reader here is the PRIVILEGED side, and its peer is the
// process that just parsed an attacker's PDF.
//
// The package is not untested: internal/agent/agent_test.go exercises round-trip, the oversize prefix and
// a truncated frame, reaching 82.6%. What was missing is the unstructured half, plus WriteFrame's own
// refusal path.

func FuzzReadFrame(f *testing.F) {
	var seed bytes.Buffer
	if err := ipc.WriteFrame(&seed, &corev1.ClassifyRequest{
		RequestId: "r1", EventId: "e1",
		Subject: &corev1.ClassifyRequest_Path{Path: "/tmp/x"},
	}); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add([]byte{0, 0, 0, 0})             // a zero-length frame: valid, an empty message
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // the allocation primitive, header only
	f.Add([]byte{0, 0, 0, 8})             // a declared body that never arrives
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg corev1.ClassifyRequest
		err := ipc.ReadFrame(bytes.NewReader(data), &msg)
		if err != nil {
			return
		}
		// Anything that DECODES must respect the bound the decoder claims to enforce, and must re-encode:
		// a message that cannot be written back is one the decoder invented.
		var back bytes.Buffer
		if werr := ipc.WriteFrame(&back, &msg); werr != nil {
			t.Fatalf("decoded a message that cannot be re-encoded: %v", werr)
		}
		if back.Len() > ipc.MaxFrameSize+4 {
			t.Fatalf("re-encoding a decoded message exceeded the frame bound: %d bytes", back.Len())
		}
	})
}

// A declared length is checked BEFORE the allocation it would drive. The sibling test covers 0xFFFFFFFF;
// this covers the boundary itself, where an off-by-one is the plausible mistake.
func TestTheFrameBoundIsCheckedAtItsExactEdge(t *testing.T) {
	for _, tc := range []struct {
		name    string
		declare uint32
		wantErr bool
	}{
		{"one under the cap", ipc.MaxFrameSize - 1, false},
		{"exactly the cap", ipc.MaxFrameSize, false},
		{"one over the cap", ipc.MaxFrameSize + 1, true},
		{"absurd", 0xFFFFFFFF, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := binary.BigEndian.AppendUint32(nil, tc.declare)
			var msg corev1.ClassifyRequest
			err := ipc.ReadFrame(bytes.NewReader(hdr), &msg)

			if tc.wantErr {
				if !errors.Is(err, ipc.ErrFrameTooLarge) {
					t.Fatalf("declaring %d gave %v, want ErrFrameTooLarge", tc.declare, err)
				}
				return
			}
			// Within the cap the length is ACCEPTED, so the failure must be the missing body — proving the
			// bound did not reject it, without ever supplying a megabyte.
			if errors.Is(err, ipc.ErrFrameTooLarge) {
				t.Fatalf("declaring %d was rejected as too large; the cap is off by one", tc.declare)
			}
			if err == nil {
				t.Fatalf("declaring %d with no body was accepted", tc.declare)
			}
		})
	}
}

// "The size check happens BEFORE allocation" is the package's central claim, and NO ORDINARY TEST CAN SEE
// IT. Whether the bound is checked before or after `make([]byte, n)`, the caller gets the same
// ErrFrameTooLarge — the only difference is that the buggy order allocates the memory first, which is the
// entire attack. The sibling test is called TestOversizedFrameRejectedWithoutAllocating and cannot in fact
// tell; it asserts the error, which both orders produce.
//
// So this measures the thing directly. A frame declaring 64 MiB is rejected; if the allocation happened
// first, TotalAlloc jumps by 64 MiB. The threshold is deliberately loose (8 MiB) because TotalAlloc is
// process-wide and the runtime allocates on its own — but the gap between "nothing" and "64 MiB" is three
// orders of magnitude wider than that noise.
//
// 64 MiB rather than the 4 GiB the sibling test declares: enough to be unmistakable, small enough that a
// regression makes the test FAIL rather than making the machine swap.
func TestTheBoundIsCheckedBeforeTheAllocationHappens(t *testing.T) {
	const declared = 64 << 20
	hdr := binary.BigEndian.AppendUint32(nil, declared)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var msg corev1.ClassifyRequest
	err := ipc.ReadFrame(bytes.NewReader(hdr), &msg)

	runtime.ReadMemStats(&after)

	if !errors.Is(err, ipc.ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Fatalf("rejecting a %d-byte frame allocated %d bytes — the bound is being checked AFTER the "+
			"allocation it exists to prevent, so a peer can still make the privileged process reserve "+
			"whatever it names", declared, grew)
	}
}

// WriteFrame's own refusal was the uncovered branch. It matters on the way OUT too: a worker that emitted
// an over-cap frame would produce something its own reader is required to reject, so the failure would
// surface on the privileged side as a peer that had gone wrong, rather than here as a message too big.
func TestWriteFrameRefusesAnOversizeMessage(t *testing.T) {
	big := &corev1.ClassifyRequest{
		RequestId: "r1",
		Subject:   &corev1.ClassifyRequest_Path{Path: strings.Repeat("A", ipc.MaxFrameSize+1024)},
	}
	err := ipc.WriteFrame(io.Discard, big)
	if !errors.Is(err, ipc.ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}

	// Nothing must be written when the frame is refused: a header without its body would desynchronise the
	// stream, and the reader would take the next message's first four bytes as a length.
	var buf bytes.Buffer
	if err := ipc.WriteFrame(&buf, big); err == nil {
		t.Fatal("an oversize frame was written")
	}
	if buf.Len() != 0 {
		t.Fatalf("%d bytes were written for a refused frame; a partial write desynchronises the stream "+
			"and the reader would read the NEXT message's bytes as a length prefix", buf.Len())
	}
}

// A zero-length frame is legitimate — an empty message — and must not be confused with EOF.
func TestAZeroLengthFrameIsAValidEmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	if err := ipc.WriteFrame(&buf, &corev1.ClassifyRequest{}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4 {
		t.Fatalf("an empty message framed to %d bytes, want just the 4-byte header", buf.Len())
	}
	var got corev1.ClassifyRequest
	if err := ipc.ReadFrame(&buf, &got); err != nil {
		t.Fatalf("a zero-length frame was not readable: %v", err)
	}
	if got.GetRequestId() != "" {
		t.Fatalf("decoded %+v from an empty frame", &got)
	}
}

// A header that is itself cut short is a different failure from a missing body, and both have to be errors
// rather than a zero-value message handed to the privileged side as though it had been received.
func TestATruncatedHeaderIsAnError(t *testing.T) {
	for n := 0; n < 4; n++ {
		var msg corev1.ClassifyRequest
		if err := ipc.ReadFrame(bytes.NewReader(make([]byte, n)), &msg); err == nil {
			t.Fatalf("a %d-byte header was accepted", n)
		}
	}
}
