// Package execipc carries exec verdicts between the PRIVILEGED exec gate and the UNPRIVILEGED engine
// (HIPS-3 increment 2a), so an inline exec decision can come from the full pipeline instead of only the
// static deny-list the privileged binary holds.
//
// The framing is hand-rolled and fixed-shape on purpose. The privileged side of this socket holds
// CAP_SYS_ADMIN and answers fanotify permission events, so a memory bug in anything it decodes is host
// compromise — the failure mode behind repeated RCEs in comparable products (ClamAV CVE-2025-20260, a
// PDF-parser heap overflow in a privileged daemon). The existing internal/agent/ipc uses protobuf, which
// is fine THERE because the unprivileged worker holds it; putting a wire-format decoder in the agent would
// undo the whole point of splitting the binaries. So: fixed-width fields, one bounded copy, no
// self-describing structure, and nothing from encoding/* beyond encoding/binary.
//
// What crosses: a pid and an executable path (metadata, D10/D29) one way, a single verdict byte the other.
// Never content.
package execipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire constants. magic + version make a desynchronized or foreign stream fail loudly instead of being
// interpreted as a verdict.
const (
	magic   uint32 = 0x4F535847 // "OSXG" — OpenShield eXec Gate
	version byte   = 1

	// MaxPathLen bounds the executable path a request may carry. A length prefix from a peer is an
	// allocation primitive if it is not bounded, and this one is read by the privileged process.
	MaxPathLen = 4096

	reqHeaderLen  = 4 + 1 + 8 + 4 + 2 // magic, version, request id, pid, path length
	respFrameLen  = 4 + 1 + 8 + 1     // magic, version, request id, verdict
	maxReqFrameLn = reqHeaderLen + MaxPathLen
)

// Verdict is the answer the engine returns for one execution. Deliberately two values: this transport
// carries a decision that has ALREADY been reduced by the pipeline's closed action set (only DENY_EXEC
// blocks, D14). Widening it here would move policy into the transport.
type Verdict byte

const (
	VerdictAllow Verdict = 0
	VerdictDeny  Verdict = 1
)

var (
	// ErrBadMagic / ErrBadVersion / ErrShortFrame / ErrPathTooLong are all TERMINAL for a frame. None of
	// them is ever resolved into a verdict: the gate must fail open loudly, never guess (see Client).
	ErrBadMagic    = errors.New("execipc: bad frame magic")
	ErrBadVersion  = errors.New("execipc: unsupported protocol version")
	ErrShortFrame  = errors.New("execipc: truncated frame")
	ErrPathTooLong = errors.New("execipc: path exceeds maximum length")
	// ErrIDMismatch means the peer answered a DIFFERENT request than the one pending. It is fatal to the
	// connection, not just the request — see Client.evaluate.
	ErrIDMismatch = errors.New("execipc: response request-id does not match the pending request")
	// ErrBadVerdict guards the verdict byte: an unknown value is an error, NOT a default-allow, so a
	// protocol slip cannot silently become a permissive answer.
	ErrBadVerdict = errors.New("execipc: unrecognized verdict byte")
)

// Request is one exec-permission question: which pid is executing which path.
type Request struct {
	ID   uint64
	PID  int32
	Path string
}

// Response is the engine's answer, tagged with the id it answers.
type Response struct {
	ID      uint64
	Verdict Verdict
}

// WriteRequest encodes a request. The path length is bounded here too, so an over-long path is a local
// error rather than a frame the peer must defend against.
func WriteRequest(w io.Writer, r Request) error {
	if len(r.Path) > MaxPathLen {
		return fmt.Errorf("%w: %d bytes", ErrPathTooLong, len(r.Path))
	}
	buf := make([]byte, reqHeaderLen+len(r.Path))
	binary.BigEndian.PutUint32(buf[0:4], magic)
	buf[4] = version
	binary.BigEndian.PutUint64(buf[5:13], r.ID)
	binary.BigEndian.PutUint32(buf[13:17], uint32(r.PID))
	binary.BigEndian.PutUint16(buf[17:19], uint16(len(r.Path)))
	copy(buf[19:], r.Path)
	_, err := w.Write(buf)
	return err
}

// ReadRequest decodes a request.
//
// Order matters: magic, then version, then the LENGTH CHECK, and only then the allocation. Reversing the
// last two would let a peer request an arbitrary allocation with two bytes.
func ReadRequest(r io.Reader) (Request, error) {
	var hdr [reqHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Request{}, frameErr(err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != magic {
		return Request{}, ErrBadMagic
	}
	if hdr[4] != version {
		return Request{}, fmt.Errorf("%w: %d", ErrBadVersion, hdr[4])
	}
	req := Request{
		ID:  binary.BigEndian.Uint64(hdr[5:13]),
		PID: int32(binary.BigEndian.Uint32(hdr[13:17])),
	}
	n := int(binary.BigEndian.Uint16(hdr[17:19]))
	if n > MaxPathLen {
		return Request{}, fmt.Errorf("%w: %d bytes", ErrPathTooLong, n)
	}
	if n == 0 {
		return req, nil
	}
	path := make([]byte, n)
	if _, err := io.ReadFull(r, path); err != nil {
		return Request{}, frameErr(err)
	}
	req.Path = string(path)
	return req, nil
}

// WriteResponse encodes a verdict.
func WriteResponse(w io.Writer, resp Response) error {
	var buf [respFrameLen]byte
	binary.BigEndian.PutUint32(buf[0:4], magic)
	buf[4] = version
	binary.BigEndian.PutUint64(buf[5:13], resp.ID)
	buf[13] = byte(resp.Verdict)
	_, err := w.Write(buf[:])
	return err
}

// ReadResponse decodes a verdict. An unrecognized verdict byte is an ERROR, not a default — a permissive
// default here would turn a protocol slip into a silent allow.
func ReadResponse(r io.Reader) (Response, error) {
	var buf [respFrameLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Response{}, frameErr(err)
	}
	if binary.BigEndian.Uint32(buf[0:4]) != magic {
		return Response{}, ErrBadMagic
	}
	if buf[4] != version {
		return Response{}, fmt.Errorf("%w: %d", ErrBadVersion, buf[4])
	}
	v := Verdict(buf[13])
	if v != VerdictAllow && v != VerdictDeny {
		return Response{}, fmt.Errorf("%w: %d", ErrBadVerdict, buf[13])
	}
	return Response{ID: binary.BigEndian.Uint64(buf[5:13]), Verdict: v}, nil
}

// frameErr normalizes a short read into ErrShortFrame while leaving real I/O errors (including
// deadline expiry, which the client must be able to distinguish) intact.
func frameErr(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %v", ErrShortFrame, err)
	}
	return err
}
