// Package openipc carries file-open verdicts between the PRIVILEGED open gate and the UNPRIVILEGED
// engine (B2), so an inline file-open decision comes from the full pipeline rather than from anything
// the privileged binary could decide alone.
//
// It is deliberately the exec bridge's twin (internal/agent/execipc) — fixed-shape framing, magic and
// version so a desynchronized stream fails loudly, bounded lengths so a peer's length prefix is never
// an allocation primitive, and nothing from encoding/* beyond encoding/binary. The privileged side
// holds CAP_SYS_ADMIN and answers permission events, so a memory bug in anything it decodes is host
// compromise.
//
// # THIS ONE CARRIES CONTENT, AND THE EXEC BRIDGE DOES NOT
//
// A request carries a bounded PREFIX of the file being opened. That is a real widening over execipc,
// whose doc ends "Never content", and it is accepted for a reason that is structural rather than
// convenient:
//
// The alternative is for the engine to open the path itself, and that is unsafe twice over. It raises
// a SECOND permission event, which the same gate must answer, which opens the file again — a deadlock
// inside a window that is UNINTERRUPTIBLE, so the machine does not recover. And it is a TOCTOU hole:
// the path may name a different file by then, so the gate would authorize what it inspected while the
// kernel releases what it did not.
//
// The agent already holds an open descriptor for the exact inode — the kernel handed it one with the
// event. Reading a bounded prefix from that descriptor performs no new open, so no second event can be
// raised, and refers to the right file by construction.
//
// # THE DIRECTION IS WHAT MAKES IT SAFE
//
// Content travels PRIVILEGED → UNPRIVILEGED. The agent WRITES bytes it read; it never decodes them. In
// the other direction it decodes exactly one fixed-width response frame carrying one verdict byte. So
// the dangerous operation — interpreting untrusted input in the privileged process — is unchanged from
// execipc, and D13 holds: the agent holds bytes, and only the worker parses them (D72).
//
// The prefix never becomes part of an Event, never reaches the ledger, and never crosses the bus
// (D10/D29). It exists only for the duration of one permission window.
package openipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire constants.
const (
	magic   uint32 = 0x4F534F47 // "OSOG" — OpenShield Open Gate
	version byte   = 1

	// MaxPathLen bounds the path a request may carry.
	MaxPathLen = 4096

	// MaxPrefixLen bounds the content prefix. It is the ceiling on what one permission window can move
	// across the socket, and therefore part of the budget: a bigger prefix is a longer window, and the
	// window blocks a process uninterruptibly. 64 KiB is far more than any detector needs to fire on a
	// file's head and small enough that the copy is not what makes the window long.
	MaxPrefixLen = 64 << 10

	reqHeaderLen = 4 + 1 + 8 + 4 + 2 + 4 // magic, version, id, pid, path length, prefix length
	respFrameLen = 4 + 1 + 8 + 1         // magic, version, id, verdict
)

// Verdict is the answer for one open. Two values, for the same reason execipc has two: the pipeline's
// closed action set has already reduced the decision, and widening it here would move policy into the
// transport.
type Verdict byte

const (
	VerdictAllow Verdict = 0
	VerdictDeny  Verdict = 1
)

var (
	// Every one of these is TERMINAL for a frame and is never resolved into a verdict. The gate fails
	// open loudly instead of guessing — a guessed ALLOW is a silent hole and a guessed DENY hangs a
	// process that did nothing wrong.
	ErrBadMagic      = errors.New("openipc: bad frame magic")
	ErrBadVersion    = errors.New("openipc: unsupported protocol version")
	ErrShortFrame    = errors.New("openipc: truncated frame")
	ErrPathTooLong   = errors.New("openipc: path exceeds maximum length")
	ErrPrefixTooLong = errors.New("openipc: content prefix exceeds maximum length")
	ErrBadVerdict    = errors.New("openipc: unrecognized verdict byte")
	// ErrIDMismatch means the peer answered a DIFFERENT request than the one pending — fatal to the
	// connection, not merely to the request.
	ErrIDMismatch = errors.New("openipc: response request-id does not match the pending request")
)

// Request is one file-open question: which pid is opening which path, and the bounded head of it.
type Request struct {
	ID     uint64
	PID    int32
	Path   string
	Prefix []byte
}

// Response is the engine's answer, tagged with the id it answers.
type Response struct {
	ID      uint64
	Verdict Verdict
}

// WriteRequest encodes a request. Both lengths are bounded HERE, so an over-long field is a local error
// rather than a frame the peer has to defend against.
func WriteRequest(w io.Writer, r Request) error {
	if len(r.Path) > MaxPathLen {
		return fmt.Errorf("%w: %d bytes", ErrPathTooLong, len(r.Path))
	}
	if len(r.Prefix) > MaxPrefixLen {
		return fmt.Errorf("%w: %d bytes", ErrPrefixTooLong, len(r.Prefix))
	}
	buf := make([]byte, reqHeaderLen+len(r.Path)+len(r.Prefix))
	binary.BigEndian.PutUint32(buf[0:4], magic)
	buf[4] = version
	binary.BigEndian.PutUint64(buf[5:13], r.ID)
	binary.BigEndian.PutUint32(buf[13:17], uint32(r.PID))
	binary.BigEndian.PutUint16(buf[17:19], uint16(len(r.Path)))
	binary.BigEndian.PutUint32(buf[19:23], uint32(len(r.Prefix)))
	copy(buf[reqHeaderLen:], r.Path)
	copy(buf[reqHeaderLen+len(r.Path):], r.Prefix)
	_, err := w.Write(buf)
	return err
}

// ReadRequest decodes one request. It is read by the UNPRIVILEGED engine, and it still validates every
// length before allocating: the privileged side is not the only one worth protecting, and a decoder
// that is careful only where it must be is a decoder someone will later move.
func ReadRequest(r io.Reader) (Request, error) {
	var head [reqHeaderLen]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Request{}, frameErr(err)
	}
	if got := binary.BigEndian.Uint32(head[0:4]); got != magic {
		return Request{}, fmt.Errorf("%w: %#08x", ErrBadMagic, got)
	}
	if head[4] != version {
		return Request{}, fmt.Errorf("%w: %d", ErrBadVersion, head[4])
	}
	// BOUNDED IN uint64, THEN NARROWED. `int(binary.BigEndian.Uint32(...))` was the original, and on a
	// 32-bit platform `int` is 32 bits: a declared prefix length of 0xFFFFFFFF becomes -1, the ceiling
	// check reads `-1 > 65536` and PASSES, `make([]byte, pathLen-1)` allocates one byte short, and
	// `body[:pathLen]` panics — `slice bounds out of range [:2] with capacity 1`.
	//
	// TestADeclaredLengthBeyondTheBoundIsRefusedBeforeAllocating exists to catch exactly this and had
	// been passing, because nothing ever ran the suite on a 32-bit architecture. `GOARCH=386` and
	// `GOARCH=arm` both compile the agent today. The path length is a uint16 and was never at risk,
	// which is why only one of the two lengths was wrong.
	pathLen64 := uint64(binary.BigEndian.Uint16(head[17:19]))
	prefixLen64 := uint64(binary.BigEndian.Uint32(head[19:23]))
	if pathLen64 > MaxPathLen {
		return Request{}, fmt.Errorf("%w: %d bytes", ErrPathTooLong, pathLen64)
	}
	if prefixLen64 > MaxPrefixLen {
		return Request{}, fmt.Errorf("%w: %d bytes", ErrPrefixTooLong, prefixLen64)
	}
	// Safe to narrow now: both are proved to sit under their ceilings, which fit in an int everywhere.
	pathLen, prefixLen := int(pathLen64), int(prefixLen64)
	body := make([]byte, pathLen+prefixLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return Request{}, frameErr(err)
	}
	return Request{
		ID:     binary.BigEndian.Uint64(head[5:13]),
		PID:    int32(binary.BigEndian.Uint32(head[13:17])),
		Path:   string(body[:pathLen]),
		Prefix: body[pathLen:],
	}, nil
}

// WriteResponse encodes one verdict.
func WriteResponse(w io.Writer, resp Response) error {
	var buf [respFrameLen]byte
	binary.BigEndian.PutUint32(buf[0:4], magic)
	buf[4] = version
	binary.BigEndian.PutUint64(buf[5:13], resp.ID)
	buf[13] = byte(resp.Verdict)
	_, err := w.Write(buf[:])
	return err
}

// ReadResponse decodes one verdict. THIS is the frame the privileged process reads, so it is the one
// that must not be talked into anything: fixed width, no length from the peer, and an unrecognized
// verdict byte is an error rather than a default.
func ReadResponse(r io.Reader) (Response, error) {
	var buf [respFrameLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Response{}, frameErr(err)
	}
	if got := binary.BigEndian.Uint32(buf[0:4]); got != magic {
		return Response{}, fmt.Errorf("%w: %#08x", ErrBadMagic, got)
	}
	if buf[4] != version {
		return Response{}, fmt.Errorf("%w: %d", ErrBadVersion, buf[4])
	}
	v := Verdict(buf[13])
	if v != VerdictAllow && v != VerdictDeny {
		// NOT defaulted to allow. A protocol slip must not silently become a permissive answer; the
		// caller fails open on the ERROR, loudly and audited, which is a different thing from a
		// verdict nobody noticed was invented.
		return Response{}, fmt.Errorf("%w: %d", ErrBadVerdict, buf[13])
	}
	return Response{ID: binary.BigEndian.Uint64(buf[5:13]), Verdict: v}, nil
}

// frameErr turns a short read into ErrShortFrame while leaving EOF distinguishable, so a closed
// connection and a malformed frame are not confused.
func frameErr(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrShortFrame
	}
	return err
}
