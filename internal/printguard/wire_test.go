package printguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRoundTripPreservesEveryField(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"typical", Request{ID: 42, Printer: "HP_LaserJet", User: "alice", HasTitle: true, Job: []byte("%PDF-1.4\n")}},
		{"empty strings and job", Request{ID: 1}},
		{"no title", Request{ID: 7, Printer: "p", User: "u", HasTitle: false, Job: []byte{0}}},
		{"max-length fields", Request{ID: 99, Printer: strings.Repeat("p", MaxFieldLen), User: strings.Repeat("u", MaxFieldLen)}},
		{"job with NULs and high bytes", Request{ID: 3, Job: []byte{0x00, 0xff, 0x00, 0x80}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteRequest(&buf, tc.req); err != nil {
				t.Fatalf("WriteRequest: %v", err)
			}
			got, err := ReadRequest(&buf)
			if err != nil {
				t.Fatalf("ReadRequest: %v", err)
			}
			if got.ID != tc.req.ID || got.Printer != tc.req.Printer || got.User != tc.req.User || got.HasTitle != tc.req.HasTitle {
				t.Errorf("metadata round trip: got %+v want %+v", Request{got.ID, got.Printer, got.User, got.HasTitle, nil}, Request{tc.req.ID, tc.req.Printer, tc.req.User, tc.req.HasTitle, nil})
			}
			if !bytes.Equal(got.Job, tc.req.Job) {
				t.Errorf("job round trip: got %q want %q", got.Job, tc.req.Job)
			}
			if buf.Len() != 0 {
				t.Errorf("reader left %d unconsumed bytes — the frame is not self-delimiting", buf.Len())
			}
		})
	}
}

// A length prefix from a peer is an allocation primitive unless it is checked first. These frames DECLARE a
// huge body and supply none: a reader that allocates on the declared length would consume gigabytes (or
// die) rather than returning an error.
func TestDeclaredLengthIsCheckedBeforeAllocating(t *testing.T) {
	// Two sizes on purpose. The absurd one shows what the check is really preventing; the just-over-the-bound
	// one is what makes the check's REMOVAL detectable, because a decoder without it allocates 8 MiB, hits
	// EOF and reports a truncated frame — a different error, which this test then catches.
	for _, tc := range []struct {
		name    string
		declare uint32
	}{
		{"just over the bound", MaxJobBytes + 1},
		{"absurd", 0xFFFFFFFF},
	} {
		t.Run("job length "+tc.name, func(t *testing.T) {
			frame := validHeader(1)
			frame = append(frame, 0, 0) // empty printer
			frame = append(frame, 0, 0) // empty user
			frame = append(frame, 0)    // no title
			frame = binary.BigEndian.AppendUint32(frame, tc.declare)
			// No body follows.
			if _, err := ReadRequest(bytes.NewReader(frame)); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("got %v, want ErrTooLarge", err)
			}
		})
	}
	t.Run("metadata field length", func(t *testing.T) {
		frame := validHeader(1)
		frame = binary.BigEndian.AppendUint16(frame, MaxFieldLen+1)
		if _, err := ReadRequest(bytes.NewReader(frame)); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("got %v, want ErrTooLarge", err)
		}
	})
}

func TestWriteRejectsOversizeInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"printer", Request{Printer: strings.Repeat("p", MaxFieldLen+1)}},
		{"user", Request{User: strings.Repeat("u", MaxFieldLen+1)}},
		{"job", Request{Job: make([]byte, MaxJobBytes+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := WriteRequest(io.Discard, tc.req); !errors.Is(err, ErrTooLarge) {
				t.Fatalf("got %v, want ErrTooLarge", err)
			}
		})
	}
}

func TestMalformedRequestFramesAreRejected(t *testing.T) {
	good := func() []byte {
		var b bytes.Buffer
		if err := WriteRequest(&b, Request{ID: 5, Printer: "p", User: "u", Job: []byte("job")}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		want  error
	}{
		{"bad magic", func() []byte { f := good(); f[0] ^= 0xFF; return f }(), ErrBadMagic},
		{"unsupported version", func() []byte { f := good(); f[4] = 2; return f }(), ErrBadVersion},
		{"empty", nil, ErrShortFrame},
		{"header cut short", good()[:7], ErrShortFrame},
		{"body cut short", good()[:len(good())-1], ErrShortFrame},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadRequest(bytes.NewReader(tc.frame)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResponseRoundTripAndRejection(t *testing.T) {
	for _, v := range []Verdict{VerdictAllow, VerdictDeny} {
		var buf bytes.Buffer
		if err := WriteResponse(&buf, Response{ID: 1234, Verdict: v}); err != nil {
			t.Fatal(err)
		}
		got, err := ReadResponse(&buf)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		if got.ID != 1234 || got.Verdict != v {
			t.Fatalf("got %+v, want id 1234 verdict %d", got, v)
		}
	}

	// THE ONE THAT MATTERS. An unrecognized verdict byte must be an ERROR. If it were read permissively —
	// "not deny, so allow" — then any corruption, version skew or truncation of the verdict byte would
	// silently disable print control while still looking like a decision.
	for _, b := range []byte{2, 3, 0x7f, 0xff} {
		var buf bytes.Buffer
		if err := WriteResponse(&buf, Response{ID: 1, Verdict: Verdict(b)}); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadResponse(&buf); !errors.Is(err, ErrBadVerdict) {
			t.Fatalf("verdict byte %d: got %v, want ErrBadVerdict", b, err)
		}
	}
}

func TestMalformedResponseFramesAreRejected(t *testing.T) {
	good := func() []byte {
		var b bytes.Buffer
		if err := WriteResponse(&b, Response{ID: 9, Verdict: VerdictDeny}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		want  error
	}{
		{"bad magic", func() []byte { f := good(); f[1] ^= 0xFF; return f }(), ErrBadMagic},
		{"unsupported version", func() []byte { f := good(); f[4] = 9; return f }(), ErrBadVersion},
		{"truncated", good()[:respLen-1], ErrShortFrame},
		{"empty", nil, ErrShortFrame},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadResponse(bytes.NewReader(tc.frame)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// The filter feeds this decoder bytes framed by a process it does not control, carrying a document from
// anywhere. A panic in the decoder is a crash in the print path.
func FuzzReadRequest(f *testing.F) {
	var seed bytes.Buffer
	if err := WriteRequest(&seed, Request{ID: 1, Printer: "p", User: "u", HasTitle: true, Job: []byte("hello")}); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add(validHeader(1))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ReadRequest(bytes.NewReader(data))
		if err != nil {
			return
		}
		// Anything that decodes must respect the bounds the decoder claims to enforce, and must re-encode:
		// a value that cannot be written back is one the decoder invented.
		if len(req.Printer) > MaxFieldLen || len(req.User) > MaxFieldLen || len(req.Job) > MaxJobBytes {
			t.Fatalf("decoded a frame exceeding its own bounds: printer=%d user=%d job=%d", len(req.Printer), len(req.User), len(req.Job))
		}
		if err := WriteRequest(io.Discard, req); err != nil {
			t.Fatalf("decoded a request that cannot be re-encoded: %v", err)
		}
	})
}

func FuzzReadResponse(f *testing.F) {
	var seed bytes.Buffer
	if err := WriteResponse(&seed, Response{ID: 1, Verdict: VerdictDeny}); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes())
	f.Add(make([]byte, respLen))

	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := ReadResponse(bytes.NewReader(data))
		if err != nil {
			return
		}
		if resp.Verdict != VerdictAllow && resp.Verdict != VerdictDeny {
			t.Fatalf("decoded verdict %d, which is neither allow nor deny", resp.Verdict)
		}
	})
}

func validHeader(id uint64) []byte {
	b := binary.BigEndian.AppendUint32(nil, magic)
	b = append(b, version)
	return binary.BigEndian.AppendUint64(b, id)
}
