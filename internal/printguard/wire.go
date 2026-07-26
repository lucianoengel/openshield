// Package printguard carries print-job verdicts between the CUPS filter and the engine (DLP-2b).
//
// The filter sits in the spooler's chain, where a non-zero exit ABORTS the job — that is what makes print
// control prevention rather than reporting. It must not parse the job itself: a print filter runs on
// documents from anywhere, which is exactly the attacker-controlled-bytes case the sandboxed worker exists
// for (D71/D29). So the filter streams the job here and applies a verdict; the engine classifies it.
//
// The framing mirrors internal/agent/execipc's discipline — fixed-shape header, lengths validated BEFORE
// allocation, request ids matched — but is a separate protocol on purpose: the payloads differ, and
// coupling print to the exec gate's wire format would let one ticket's change break the other's.
package printguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	magic   uint32 = 0x4F53_5052 // "OSPR"
	version byte   = 1

	// MaxJobBytes bounds what is sent for classification. A print job can be hundreds of megabytes; the
	// engine classifies the head of a very large document rather than buffering all of it. That is a real
	// detection limit and it is documented, not silently accepted.
	MaxJobBytes = 8 << 20 // 8 MiB
	// MaxFieldLen bounds each metadata string.
	MaxFieldLen = 1024

	respLen = 4 + 1 + 8 + 1
)

var (
	ErrBadMagic   = errors.New("printguard: bad frame magic")
	ErrBadVersion = errors.New("printguard: unsupported protocol version")
	ErrShortFrame = errors.New("printguard: truncated frame")
	ErrTooLarge   = errors.New("printguard: field or job exceeds its bound")
	ErrIDMismatch = errors.New("printguard: response id does not match the request")
	ErrBadVerdict = errors.New("printguard: unrecognized verdict byte")
)

// Verdict is the engine's answer for a job.
type Verdict byte

const (
	VerdictAllow Verdict = 0
	VerdictDeny  Verdict = 1
)

// Request is one print job submitted for a decision.
type Request struct {
	ID       uint64
	Printer  string
	User     string
	HasTitle bool
	Job      []byte
}

// Response is the verdict for a request id.
type Response struct {
	ID      uint64
	Verdict Verdict
}

func putStr(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(s)))
	return append(buf, s...)
}

// WriteRequest encodes a job request.
func WriteRequest(w io.Writer, r Request) error {
	if len(r.Printer) > MaxFieldLen || len(r.User) > MaxFieldLen {
		return fmt.Errorf("%w: metadata field", ErrTooLarge)
	}
	if len(r.Job) > MaxJobBytes {
		return fmt.Errorf("%w: job of %d bytes", ErrTooLarge, len(r.Job))
	}
	buf := make([]byte, 0, 32+len(r.Printer)+len(r.User)+len(r.Job))
	buf = binary.BigEndian.AppendUint32(buf, magic)
	buf = append(buf, version)
	buf = binary.BigEndian.AppendUint64(buf, r.ID)
	buf = putStr(buf, r.Printer)
	buf = putStr(buf, r.User)
	if r.HasTitle {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(r.Job)))
	buf = append(buf, r.Job...)
	_, err := w.Write(buf)
	return err
}

func readStr(r io.Reader) (string, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", frameErr(err)
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > MaxFieldLen {
		return "", fmt.Errorf("%w: %d-byte field", ErrTooLarge, n)
	}
	if n == 0 {
		return "", nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", frameErr(err)
	}
	return string(b), nil
}

// ReadRequest decodes a job request. Every length is checked against its bound BEFORE the allocation it
// would drive — a length prefix from a peer is otherwise an allocation primitive.
func ReadRequest(r io.Reader) (Request, error) {
	var hdr [13]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Request{}, frameErr(err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != magic {
		return Request{}, ErrBadMagic
	}
	if hdr[4] != version {
		return Request{}, fmt.Errorf("%w: %d", ErrBadVersion, hdr[4])
	}
	req := Request{ID: binary.BigEndian.Uint64(hdr[5:13])}
	var err error
	if req.Printer, err = readStr(r); err != nil {
		return Request{}, err
	}
	if req.User, err = readStr(r); err != nil {
		return Request{}, err
	}
	var flag [1]byte
	if _, err := io.ReadFull(r, flag[:]); err != nil {
		return Request{}, frameErr(err)
	}
	req.HasTitle = flag[0] == 1
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return Request{}, frameErr(err)
	}
	n := int(binary.BigEndian.Uint32(l[:]))
	if n > MaxJobBytes {
		return Request{}, fmt.Errorf("%w: %d-byte job", ErrTooLarge, n)
	}
	if n > 0 {
		req.Job = make([]byte, n)
		if _, err := io.ReadFull(r, req.Job); err != nil {
			return Request{}, frameErr(err)
		}
	}
	return req, nil
}

// WriteResponse encodes a verdict.
func WriteResponse(w io.Writer, resp Response) error {
	var buf [respLen]byte
	binary.BigEndian.PutUint32(buf[0:4], magic)
	buf[4] = version
	binary.BigEndian.PutUint64(buf[5:13], resp.ID)
	buf[13] = byte(resp.Verdict)
	_, err := w.Write(buf[:])
	return err
}

// ReadResponse decodes a verdict. An unknown verdict byte is an error, never a permissive default.
func ReadResponse(r io.Reader) (Response, error) {
	var buf [respLen]byte
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

func frameErr(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %v", ErrShortFrame, err)
	}
	return err
}
