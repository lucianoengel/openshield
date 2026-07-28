package openipc

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestRequestRoundTrips including the content prefix, which is what distinguishes this wire from the
// exec one and is therefore the part most worth pinning.
func TestRequestRoundTrips(t *testing.T) {
	want := Request{ID: 42, PID: 1234, Path: "/srv/data/report.csv", Prefix: []byte("name,cpf\nalice,1")}
	var buf bytes.Buffer
	if err := WriteRequest(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.PID != want.PID || got.Path != want.Path {
		t.Errorf("metadata round-trip: got %+v want %+v", got, want)
	}
	if !bytes.Equal(got.Prefix, want.Prefix) {
		t.Errorf("prefix round-trip: got %q want %q", got.Prefix, want.Prefix)
	}
}

// TestAnEmptyPrefixIsCarried: a file that is empty, or one the agent could not read, still needs a
// verdict. Encoding must not require content.
func TestAnEmptyPrefixIsCarried(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRequest(&buf, Request{ID: 1, PID: 2, Path: "/x", Prefix: nil}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Prefix) != 0 || got.Path != "/x" {
		t.Errorf("got %+v", got)
	}
}

// TestOverLongFieldsAreLocalErrors — bounded at the ENCODER, so an over-long field never becomes a
// frame the peer has to defend against.
func TestOverLongFieldsAreLocalErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRequest(&buf, Request{Path: strings.Repeat("a", MaxPathLen+1)}); !errors.Is(err, ErrPathTooLong) {
		t.Errorf("over-long path: got %v want ErrPathTooLong", err)
	}
	if err := WriteRequest(&buf, Request{Prefix: make([]byte, MaxPrefixLen+1)}); !errors.Is(err, ErrPrefixTooLong) {
		t.Errorf("over-long prefix: got %v want ErrPrefixTooLong", err)
	}
}

// TestADeclaredLengthBeyondTheBoundIsRefusedBeforeAllocating.
//
// The decoder must not trust a peer's length prefix. Hand-crafted rather than produced by WriteRequest,
// because WriteRequest refuses to make this frame — which is the point: the check has to exist on BOTH
// sides, or it only holds against peers that share our encoder.
func TestADeclaredLengthBeyondTheBoundIsRefusedBeforeAllocating(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRequest(&buf, Request{ID: 1, PID: 1, Path: "/x", Prefix: []byte("hi")}); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	// Overwrite the prefix length with something enormous.
	frame[19], frame[20], frame[21], frame[22] = 0xff, 0xff, 0xff, 0xff
	if _, err := ReadRequest(bytes.NewReader(frame)); !errors.Is(err, ErrPrefixTooLong) {
		t.Errorf("a declared prefix length of 4 GiB was not refused: %v", err)
	}
}

// TestAForeignOrDesynchronizedStreamFailsLoudly.
func TestAForeignOrDesynchronizedStreamFailsLoudly(t *testing.T) {
	if _, err := ReadRequest(bytes.NewReader(bytes.Repeat([]byte{0}, reqHeaderLen))); !errors.Is(err, ErrBadMagic) {
		t.Errorf("zeroed frame: got %v want ErrBadMagic", err)
	}
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Response{ID: 1, Verdict: VerdictAllow}); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	frame[4] = 99 // a version this build does not speak
	if _, err := ReadResponse(bytes.NewReader(frame)); !errors.Is(err, ErrBadVersion) {
		t.Errorf("foreign version: got %v want ErrBadVersion", err)
	}
}

// TestAnUnrecognizedVerdictIsAnErrorNotAnAllow.
//
// This is the one that matters most on the response path: it is read by the PRIVILEGED process, and a
// protocol slip that defaulted to allow would be a silent hole nobody could see from the outside.
func TestAnUnrecognizedVerdictIsAnErrorNotAnAllow(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf, Response{ID: 7, Verdict: VerdictAllow}); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	frame[13] = 200
	resp, err := ReadResponse(bytes.NewReader(frame))
	if !errors.Is(err, ErrBadVerdict) {
		t.Fatalf("an unrecognized verdict byte returned %+v, %v — it must be an ERROR, so the caller "+
			"fails open loudly and audits, rather than acting on a verdict nobody noticed was invented",
			resp, err)
	}
}

// TestATruncatedFrameIsShortNotEmpty: a closed connection and a malformed frame call for different
// responses, so they must be distinguishable.
func TestATruncatedFrameIsShortNotEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRequest(&buf, Request{ID: 1, PID: 1, Path: "/some/path", Prefix: []byte("abcd")}); err != nil {
		t.Fatal(err)
	}
	frame := buf.Bytes()
	if _, err := ReadRequest(bytes.NewReader(frame[:len(frame)-3])); !errors.Is(err, ErrShortFrame) {
		t.Errorf("truncated body: got %v want ErrShortFrame", err)
	}
}
