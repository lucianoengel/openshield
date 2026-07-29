package openipc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FUZZING BOTH DIRECTIONS OF THE OPEN-GATE WIRE, ranked honestly.
//
// ReadResponse is the frame the PRIVILEGED process decodes — `cmd/openshield-agent` is the client on
// this socket, so it reads responses and never requests. It is fixed-width with no peer-supplied
// length, which is the design's deliberate asymmetry (see the package doc) rather than an accident: a
// compromised engine cannot hand the agent a length to allocate on. Fuzzing it confirms the claim
// instead of restating it.
//
// ReadRequest is decoded by the UNPRIVILEGED engine, and it is the only content-bearing frame in the
// system — it carries up to MaxPrefixLen bytes of a file someone else wrote. Lower blast radius, more
// hostile input.

// FuzzReadResponse drives the decoder the privileged agent runs.
func FuzzReadResponse(f *testing.F) {
	var valid bytes.Buffer
	_ = WriteResponse(&valid, Response{ID: 7, Verdict: VerdictDeny})
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, respFrameLen-1)) // one byte short
	f.Add(make([]byte, respFrameLen))   // right length, zero magic
	bad := append([]byte{}, valid.Bytes()...)
	bad[13] = 9 // a verdict byte that is neither allow nor deny
	f.Add(bad)

	f.Fuzz(func(t *testing.T, in []byte) {
		resp, err := ReadResponse(bytes.NewReader(in))
		if err != nil {
			return
		}
		// AN INVENTED VERDICT IS THE FAILURE THAT MATTERS. A protocol slip must never resolve into a
		// permissive answer nobody chose: the caller fails open on the ERROR, loudly and audited, which
		// is a different thing from an allow that was decoded out of noise.
		if resp.Verdict != VerdictAllow && resp.Verdict != VerdictDeny {
			t.Fatalf("ReadResponse returned verdict %d with no error — a byte outside the closed set "+
				"became an answer the gate will act on", resp.Verdict)
		}
		// AND THE DECODE IS STABLE. Re-encoding what was decoded must produce a frame that decodes
		// identically; if it does not, the encoder and decoder disagree about the format and the
		// disagreement is invisible from either side alone.
		var again bytes.Buffer
		if err := WriteResponse(&again, resp); err != nil {
			t.Fatalf("re-encoding a decoded response failed: %v", err)
		}
		round, err := ReadResponse(bytes.NewReader(again.Bytes()))
		if err != nil || round != resp {
			t.Fatalf("decode/encode/decode is not stable: %+v -> %+v (err %v)", resp, round, err)
		}
	})
}

// FuzzReadRequest drives the engine's decoder — the only frame carrying file content.
func FuzzReadRequest(f *testing.F) {
	var valid bytes.Buffer
	_ = WriteRequest(&valid, Request{ID: 1, PID: 42, Path: "/watched/x", Prefix: []byte("data")})
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, reqHeaderLen-1))
	// A header declaring the maximum of both lengths and supplying neither. This is the allocation
	// question: a decoder that sizes a buffer from the header before reading the body would commit
	// MaxPathLen+MaxPrefixLen for a frame that never arrives.
	huge := append([]byte{}, valid.Bytes()[:reqHeaderLen]...)
	huge[17], huge[18] = 0xFF, 0xFF                                 // path length
	huge[19], huge[20], huge[21], huge[22] = 0xFF, 0xFF, 0xFF, 0xFF // prefix length
	f.Add(huge)

	// A FRAME THAT IS OVER THE CEILING AND COMPLETE, body and all.
	//
	// Without it the bound assertion below CANNOT FAIL and is therefore decoration. Every other seed
	// declares a huge length and supplies no body, so `io.ReadFull` errors first and the assertion is
	// never reached — which is what happened: raising the ceiling in ReadRequest by a factor of sixteen
	// did not fail this target until this seed existed. The fuzzer would not have built a 64 KiB input
	// on its own inside any budget worth running.
	overLen := uint32(MaxPrefixLen + 1)
	over := make([]byte, reqHeaderLen+int(overLen))
	copy(over, valid.Bytes()[:reqHeaderLen])
	over[17], over[18] = 0, 0 // no path
	binary.BigEndian.PutUint32(over[19:23], overLen)
	f.Add(over)

	f.Fuzz(func(t *testing.T, in []byte) {
		req, err := ReadRequest(bytes.NewReader(in))
		if err != nil {
			return
		}
		// THE DECLARED BOUNDS ARE THE ALLOCATION BOUNDS. Exceeding them is not a formatting matter: a
		// peer's length prefix that is not bounded is an allocation primitive.
		if len(req.Path) > MaxPathLen {
			t.Fatalf("ReadRequest accepted a %d-byte path against a %d-byte ceiling", len(req.Path), MaxPathLen)
		}
		if len(req.Prefix) > MaxPrefixLen {
			t.Fatalf("ReadRequest accepted a %d-byte content prefix against a %d-byte ceiling — the "+
				"ceiling is also the bound on how long one permission window can be, so exceeding it "+
				"lengthens a window that blocks a process uninterruptibly",
				len(req.Prefix), MaxPrefixLen)
		}
		var again bytes.Buffer
		if err := WriteRequest(&again, req); err != nil {
			t.Fatalf("re-encoding a decoded request failed: %v", err)
		}
		round, err := ReadRequest(bytes.NewReader(again.Bytes()))
		if err != nil {
			t.Fatalf("a re-encoded request did not decode: %v", err)
		}
		if round.ID != req.ID || round.PID != req.PID || round.Path != req.Path ||
			!bytes.Equal(round.Prefix, req.Prefix) {
			t.Fatalf("decode/encode/decode is not stable: %+v -> %+v", req, round)
		}
	})
}
