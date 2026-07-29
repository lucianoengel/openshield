package execipc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// THE EXEC GATE'S WIRE, both directions. Same shape as openipc's targets and for the same reasons; the
// difference is that this transport carries NO content — its doc ends "Never content" — so a request is
// a path and nothing else.
//
// ReadResponse is what the PRIVILEGED agent decodes (it is the client here too). ReadRequest is the
// engine's.

// FuzzReadResponse drives the decoder the privileged exec gate runs.
func FuzzReadResponse(f *testing.F) {
	var valid bytes.Buffer
	_ = WriteResponse(&valid, Response{ID: 3, Verdict: VerdictDeny})
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, respFrameLen-1))
	f.Add(make([]byte, respFrameLen))
	bad := append([]byte{}, valid.Bytes()...)
	bad[13] = 0xFF
	f.Add(bad)

	f.Fuzz(func(t *testing.T, in []byte) {
		resp, err := ReadResponse(bytes.NewReader(in))
		if err != nil {
			return
		}
		if resp.Verdict != VerdictAllow && resp.Verdict != VerdictDeny {
			t.Fatalf("ReadResponse returned verdict %d with no error — a byte outside the closed set "+
				"became a decision to refuse or permit an execution", resp.Verdict)
		}
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

// FuzzReadRequest drives the engine's decoder for exec questions.
func FuzzReadRequest(f *testing.F) {
	var valid bytes.Buffer
	_ = WriteRequest(&valid, Request{ID: 1, PID: 42, Path: "/usr/bin/nc"})
	f.Add(valid.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, reqHeaderLen-1))
	huge := append([]byte{}, valid.Bytes()[:reqHeaderLen]...)
	huge[17], huge[18] = 0xFF, 0xFF // a path length no body follows
	f.Add(huge)

	// OVER THE CEILING AND COMPLETE. The seed above declares a huge length and supplies no body, so
	// io.ReadFull errors first and the bound assertion below is never reached — an assertion that cannot
	// fail. This one carries the bytes it claims, so removing the ceiling check makes the target fail.
	over := make([]byte, reqHeaderLen+MaxPathLen+1)
	copy(over, valid.Bytes()[:reqHeaderLen])
	binary.BigEndian.PutUint16(over[17:19], uint16(MaxPathLen+1))
	for i := reqHeaderLen; i < len(over); i++ {
		over[i] = 'a'
	}
	f.Add(over)

	f.Fuzz(func(t *testing.T, in []byte) {
		req, err := ReadRequest(bytes.NewReader(in))
		if err != nil {
			return
		}
		if len(req.Path) > MaxPathLen {
			t.Fatalf("ReadRequest accepted a %d-byte path against a %d-byte ceiling — an unbounded "+
				"length prefix from a peer is an allocation primitive", len(req.Path), MaxPathLen)
		}
		var again bytes.Buffer
		if err := WriteRequest(&again, req); err != nil {
			t.Fatalf("re-encoding a decoded request failed: %v", err)
		}
		round, err := ReadRequest(bytes.NewReader(again.Bytes()))
		if err != nil || round != req {
			t.Fatalf("decode/encode/decode is not stable: %+v -> %+v (err %v)", req, round, err)
		}
	})
}
