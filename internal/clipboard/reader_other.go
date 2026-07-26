//go:build !linux

package clipboard

import "fmt"

// NewReader has no implementation off Linux (DLP-2a is Linux-first for the MVP; Windows/macOS clipboard
// capture rides the cross-platform enrichment ticket). It returns ErrUnsupported rather than a reader that
// yields an empty clipboard — a producer must be able to tell "I cannot look" from "nothing was there", or
// it silently observes nothing forever.
func NewReader() (Reader, error) {
	return nil, fmt.Errorf("%w: clipboard capture is Linux-only for now", ErrUnsupported)
}

// NewReaderFor likewise has no implementation off Linux.
func NewReaderFor(display string) (Reader, error) {
	return nil, fmt.Errorf("%w: clipboard capture is Linux-only for now (asked for %q)", ErrUnsupported, display)
}
