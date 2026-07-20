// Package ipc carries classification requests between the privileged agent and
// the unprivileged parser worker.
//
// The framing is deliberately dull: a 4-byte big-endian length followed by a
// protobuf message, with a hard cap on frame size. It is the boundary between a
// process holding CAP_SYS_ADMIN and one that touches attacker-controlled files,
// so "dull" is the requirement — every feature here is an attack surface facing
// the privileged side.
//
// Note what does NOT cross this boundary: matched content. The worker returns
// detector types, confidences and counts. LocalClassification, which holds
// matched text, never leaves the worker. The privileged process therefore never
// parses attacker-controlled bytes (D13) and never holds them either.
package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// MaxFrameSize bounds a single message. A length prefix read from a less
// trusted peer is an allocation primitive if it is not bounded — this is the
// classic way a framing layer becomes a memory-exhaustion bug.
const MaxFrameSize = 1 << 20 // 1 MiB

var (
	ErrFrameTooLarge = errors.New("ipc: frame exceeds maximum size")
	ErrShortFrame    = errors.New("ipc: truncated frame")
)

// WriteFrame writes a length-prefixed protobuf message.
func WriteFrame(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("ipc marshal: %w", err)
	}
	if len(b) > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadFrame reads a length-prefixed protobuf message into m.
//
// The size check happens BEFORE allocation. Reversing that order would let a
// peer request an arbitrary allocation with four bytes — and on the privileged
// side, the peer is the process that just parsed an attacker's PDF.
func ReadFrame(r io.Reader, m proto.Message) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: wanted %d bytes", ErrShortFrame, n)
		}
		return err
	}
	return proto.Unmarshal(b, m)
}
