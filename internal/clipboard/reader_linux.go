//go:build linux

package clipboard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
)

// helperReader reads the clipboard by running the host's clipboard helper and capping its output.
type helperReader struct {
	argv    []string
	display string
	// bin is the resolved absolute path of the helper, recorded so an operator can see WHICH binary is
	// being run rather than trusting an implicit PATH lookup at every poll.
	bin string
}

// NewReader returns the clipboard reader for this session, or an error explaining why there is none.
//
// It resolves the helper ONCE, at construction: a producer that discovers a missing binary on every poll
// would log an error per interval forever, and a PATH that changes under a long-running process is a
// surprise worth not having.
func NewReader() (Reader, error) {
	switch Detect() {
	case DisplayWayland:
		return newHelperReader(waylandArgv(), DisplayWayland)
	case DisplayX11:
		return newHelperReader(x11Argv(), DisplayX11)
	default:
		return nil, fmt.Errorf("%w: no WAYLAND_DISPLAY or DISPLAY in the environment", ErrNoHelper)
	}
}

// NewReaderFor builds a reader for a NAMED display server, bypassing environment detection. It exists for
// the real-display test, which starts its own X server and must not depend on the ambient session.
func NewReaderFor(display string) (Reader, error) {
	switch display {
	case DisplayWayland:
		return newHelperReader(waylandArgv(), DisplayWayland)
	case DisplayX11:
		return newHelperReader(x11Argv(), DisplayX11)
	default:
		return nil, fmt.Errorf("%w: unknown display server %q", ErrUnsupported, display)
	}
}

func newHelperReader(argv []string, display string) (Reader, error) {
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %s not on PATH (install it to enable clipboard monitoring)", ErrNoHelper, argv[0])
	}
	return &helperReader{argv: argv, display: display, bin: bin}, nil
}

func (h *helperReader) DisplayServer() string { return h.display }

// Read runs the helper and returns at most MaxBytes.
//
// The read is capped with io.LimitReader rather than reading everything and slicing: slicing afterwards
// means the oversized content was already in memory, which is the thing the cap exists to prevent.
//
// An exit error is NOT automatically a failure. `xclip -o` exits non-zero when the selection is empty or
// unowned, which is the ordinary state of a fresh session — treating it as an error would make the producer
// log a failure per poll on any machine where nobody has copied anything yet. So a non-zero exit with no
// output is reported as an EMPTY clipboard; a non-zero exit that also wrote something is a real error,
// because then the helper is telling us two contradictory things.
func (h *helperReader) Read(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, h.bin, h.argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("clipboard: starting %s: %w", h.bin, err)
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, MaxBytes))
	// Drain any remainder so the helper is not killed mid-write by a closed pipe (a broken-pipe error would
	// otherwise masquerade as a clipboard failure).
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, fmt.Errorf("clipboard: reading from %s: %w", h.bin, readErr)
	}
	if waitErr != nil {
		if len(out) == 0 {
			return nil, nil // empty or unowned selection — the normal quiet case, not a failure
		}
		return nil, fmt.Errorf("clipboard: %s exited %v with partial output (%d bytes): %s",
			h.bin, waitErr, len(out), stderr.String())
	}
	return out, nil
}
