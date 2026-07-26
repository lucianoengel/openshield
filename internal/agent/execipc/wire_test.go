package execipc_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/execipc"
)

// TestRequestRoundTrip: the happy path, plus a zero-length path (a permission event whose path could not
// be resolved is still a question worth asking).
func TestRequestRoundTrip(t *testing.T) {
	for _, path := range []string{"/usr/bin/curl", "", strings.Repeat("a", execipc.MaxPathLen)} {
		var buf bytes.Buffer
		want := execipc.Request{ID: 42, PID: 1234, Path: path}
		if err := execipc.WriteRequest(&buf, want); err != nil {
			t.Fatalf("write (path %d bytes): %v", len(path), err)
		}
		got, err := execipc.ReadRequest(&buf)
		if err != nil {
			t.Fatalf("read (path %d bytes): %v", len(path), err)
		}
		if got != want {
			t.Errorf("round trip = %+v, want %+v", got, want)
		}
	}
}

func TestResponseRoundTrip(t *testing.T) {
	for _, v := range []execipc.Verdict{execipc.VerdictAllow, execipc.VerdictDeny} {
		var buf bytes.Buffer
		want := execipc.Response{ID: 7, Verdict: v}
		if err := execipc.WriteResponse(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := execipc.ReadResponse(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("round trip = %+v, want %+v", got, want)
		}
	}
}

// TestRequestRejectsOverLongPath proves the length bound is enforced on the WRITE side too, so an
// over-long path is a local error rather than a frame the privileged peer has to defend against.
func TestRequestRejectsOverLongPath(t *testing.T) {
	var buf bytes.Buffer
	err := execipc.WriteRequest(&buf, execipc.Request{Path: strings.Repeat("a", execipc.MaxPathLen+1)})
	if !errors.Is(err, execipc.ErrPathTooLong) {
		t.Fatalf("write over-long path err = %v, want ErrPathTooLong", err)
	}
}

// TestMalformedFramesAreRejected walks every malformed class. None of them may be resolved into a verdict:
// on the privileged side of this socket, "interpret it anyway" is how a framing layer becomes a memory bug.
func TestMalformedFramesAreRejected(t *testing.T) {
	good := func() []byte {
		var b bytes.Buffer
		if err := execipc.WriteRequest(&b, execipc.Request{ID: 1, PID: 2, Path: "/bin/sh"}); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}

	t.Run("bad magic", func(t *testing.T) {
		f := good()
		binary.BigEndian.PutUint32(f[0:4], 0xDEADBEEF)
		if _, err := execipc.ReadRequest(bytes.NewReader(f)); !errors.Is(err, execipc.ErrBadMagic) {
			t.Fatalf("err = %v, want ErrBadMagic", err)
		}
	})

	t.Run("unknown version", func(t *testing.T) {
		f := good()
		f[4] = 99
		if _, err := execipc.ReadRequest(bytes.NewReader(f)); !errors.Is(err, execipc.ErrBadVersion) {
			t.Fatalf("err = %v, want ErrBadVersion", err)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		f := good()
		if _, err := execipc.ReadRequest(bytes.NewReader(f[:10])); !errors.Is(err, execipc.ErrShortFrame) {
			t.Fatalf("err = %v, want ErrShortFrame", err)
		}
	})

	t.Run("truncated body", func(t *testing.T) {
		f := good()
		if _, err := execipc.ReadRequest(bytes.NewReader(f[:len(f)-3])); !errors.Is(err, execipc.ErrShortFrame) {
			t.Fatalf("err = %v, want ErrShortFrame", err)
		}
	})

	// The allocation-primitive case: a two-byte length claiming more than the bound must be refused
	// BEFORE any buffer of that size is created. countingReader proves nothing tried to read the claimed
	// body — if the bound were checked after allocation, the reader would be asked for those bytes.
	t.Run("over-long declared length allocates nothing", func(t *testing.T) {
		f := good()
		binary.BigEndian.PutUint16(f[17:19], uint16(execipc.MaxPathLen+1))
		r := &countingReader{r: bytes.NewReader(f)}
		_, err := execipc.ReadRequest(r)
		if !errors.Is(err, execipc.ErrPathTooLong) {
			t.Fatalf("err = %v, want ErrPathTooLong", err)
		}
		if r.reads > 1 {
			t.Errorf("reader was consulted %d times after an over-long length; the bound must be checked "+
				"before the body is read or allocated", r.reads)
		}
	})

	t.Run("unknown verdict byte is an error, not a default", func(t *testing.T) {
		var b bytes.Buffer
		if err := execipc.WriteResponse(&b, execipc.Response{ID: 1, Verdict: execipc.VerdictAllow}); err != nil {
			t.Fatal(err)
		}
		f := b.Bytes()
		f[13] = 0x7F
		if _, err := execipc.ReadResponse(bytes.NewReader(f)); !errors.Is(err, execipc.ErrBadVerdict) {
			t.Fatalf("err = %v, want ErrBadVerdict — a permissive default would turn a protocol slip "+
				"into a silent allow", err)
		}
	})
}

type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}
