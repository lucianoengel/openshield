package sandbox

import (
	"errors"
	"fmt"
	"io"
)

// Bomb-guard defaults. A legitimate document compresses maybe 10-20:1; 200:1 is
// already deep into "someone is trying something" territory.
const (
	DefaultMaxRatio    = 200       // output bytes per input byte
	DefaultMaxExpanded = 512 << 20 // 512 MiB absolute expanded ceiling
	DefaultMaxDepth    = 8         // nested-archive depth
)

// ErrBomb is returned when a decompression guard bound is crossed.
var ErrBomb = errors.New("sandbox: decompression bomb rejected")

// DecompressGuard wraps the OUTPUT of a decompressor and fails the moment
// expansion crosses a bound — before the over-limit bytes reach a parser or
// memory. It bounds expansion by ratio and by absolute size; nesting depth is
// bounded separately via EnterArchive, because depth is a property of the
// caller's recursion, not of a single stream.
//
// The raw byte ceiling (worker.limitReader) bounds a large FILE. This bounds a
// small file that expands hugely — the two are different guarantees, and a bomb
// needs the second (D13).
type DecompressGuard struct {
	r         io.Reader
	inputSize int64 // compressed size, for the ratio bound
	maxRatio  int64
	maxOut    int64
	read      int64
}

// NewDecompressGuard bounds a decompressed stream. inputSize is the compressed
// input's size, used for the ratio check; pass 0 to disable the ratio bound and
// rely on the absolute cap alone.
func NewDecompressGuard(r io.Reader, inputSize int64) *DecompressGuard {
	return &DecompressGuard{
		r:         r,
		inputSize: inputSize,
		maxRatio:  DefaultMaxRatio,
		maxOut:    DefaultMaxExpanded,
	}
}

// Read passes through until a bound would be crossed, then returns ErrBomb. The
// check happens BEFORE returning bytes to the caller: on the read that would
// take the total past a cap, the guard errors instead of delivering them.
func (g *DecompressGuard) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if n > 0 {
		g.read += int64(n)
		if g.read > g.maxOut {
			return 0, fmt.Errorf("%w: expanded output exceeded %d bytes", ErrBomb, g.maxOut)
		}
		if g.inputSize > 0 && g.read > g.inputSize*g.maxRatio {
			return 0, fmt.Errorf("%w: expansion ratio exceeded %d:1", ErrBomb, g.maxRatio)
		}
	}
	return n, err
}

// depthTracker bounds nesting depth across recursive decompression.
type depthTracker struct {
	depth int
	max   int
}

// NewDepthTracker bounds archive nesting.
func NewDepthTracker() *depthTracker { return &depthTracker{max: DefaultMaxDepth} }

// EnterArchive is called on descending into a nested archive. It returns ErrBomb
// once depth would exceed the cap, rejecting the input rather than recursing.
func (d *depthTracker) EnterArchive() error {
	d.depth++
	if d.depth > d.max {
		return fmt.Errorf("%w: archive nesting exceeded depth %d", ErrBomb, d.max)
	}
	return nil
}

// LeaveArchive is called on ascending out of a nested archive.
func (d *depthTracker) LeaveArchive() {
	if d.depth > 0 {
		d.depth--
	}
}
