// Package clipboard reads the desktop clipboard so a sensitive COPY is a detectable exfiltration event
// (DLP-2a). Copy-paste is the channel a desktop user actually reaches for, and watching directories while
// ignoring it is the gap the roadmap calls "not a DLP without the exfil channels".
//
// What this package does NOT do: parse. It hands the copied bytes to the caller, which forwards them to the
// SANDBOXED WORKER for classification (D71/D29). The bytes never reach an Event (D10) and the privileged
// agent is not involved at all (D13).
//
// The capture mechanism is a SUBPROCESS — `wl-paste` on Wayland, `xclip` on X11 — not in-process display
// bindings. That keeps display-protocol parsing out of the engine and adds no dependency, the same
// discipline the gateway already uses for nft/iptables. The costs are real and stated rather than hidden: a
// fork+exec per poll, and the host must have the helper installed.
package clipboard

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
)

// MaxBytes caps a single clipboard read.
//
// A clipboard can hold megabytes, and the process doing the reading is the one that forwards the bytes to
// another process — so an unbounded read here is a memory-exhaustion primitive driven by whatever the user
// last copied. Content beyond the cap is TRUNCATED, which can split a match at the boundary and miss a
// detection on a very large copy; that trade is accepted and documented rather than removed.
const MaxBytes = 1 << 20 // 1 MiB

// Display server tokens. Content-free metadata: which capture path observed the copy.
const (
	DisplayWayland = "wayland"
	DisplayX11     = "x11"
	DisplayNone    = ""
)

// ErrUnsupported means there is no clipboard implementation for this platform. It is deliberately DISTINCT
// from an empty clipboard: "I cannot look" and "there was nothing there" are different facts, and conflating
// them is how a producer ends up silently observing nothing.
var ErrUnsupported = errors.New("clipboard: no implementation for this platform")

// ErrNoHelper means the platform is supported but the helper binary is missing.
var ErrNoHelper = errors.New("clipboard: no clipboard helper binary found on PATH")

// Reader reads the current clipboard contents. It is an interface so the OS seam — the ONLY part that needs
// a display — is replaceable in tests, letting the producer and the whole pipeline be tested for real
// without one.
type Reader interface {
	// Read returns the clipboard contents, truncated to MaxBytes. An empty clipboard is (nil, nil).
	Read(ctx context.Context) ([]byte, error)
	// DisplayServer names the capture path, for the event's metadata.
	DisplayServer() string
}

// Detect reports which display server the environment exposes, preferring Wayland when both are present
// (a Wayland session commonly also exports DISPLAY for XWayland, and the native path is the accurate one).
// DisplayNone means no display: the caller must then DISABLE clipboard monitoring loudly rather than run
// a producer that can never observe anything.
func Detect() string {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		return DisplayWayland
	}
	if os.Getenv("DISPLAY") != "" {
		return DisplayX11
	}
	return DisplayNone
}

// waylandArgv / x11Argv are the helper invocations, extracted so they are asserted by unit tests without a
// display — the same reason the firewall-rule argv builders are separate from their execution.
//
// wl-paste: --no-newline so a trailing newline is not invented, and an explicit text type so a copied image
// is not returned as bytes we would then treat as text.
func waylandArgv() []string { return []string{"wl-paste", "--no-newline", "--type", "text/plain"} }

// xclip: -o reads (rather than writes) the CLIPBOARD selection specifically — not PRIMARY, which is the
// mouse-highlight selection and would fire on ordinary text selection rather than a deliberate copy.
func x11Argv() []string { return []string{"xclip", "-selection", "clipboard", "-o"} }

// Digest is the change-detection value for clipboard content.
//
// IMPORTANT, because the project's rules are explicit about hashes: this digest is LOCAL DEDUP STATE. It is
// never emitted, logged, or placed on any message. D10/D11 forbid treating a hash as a privacy control for
// TRANSMITTED low-entropy PII (a hashed CPF is brute-forceable) — this is not that; it answers "did the
// clipboard change?" and never leaves the process, exactly like an mtime in a FIM baseline.
func Digest(b []byte) [32]byte { return sha256.Sum256(b) }

// Watcher turns a Reader into a change stream: it reads on demand and reports content only when it DIFFERS
// from the last content it saw. Without this, every poll of an unchanged clipboard would be a fresh
// "exfiltration event", and an idle desktop would generate an alert per interval.
type Watcher struct {
	Reader Reader
	// Exclusions, when set, suppresses copies from excluded SOURCE applications — checked BEFORE the read,
	// so an excluded secret never enters this process (see exclusions.go). nil = no exclusions.
	Exclusions *Exclusions
	// Source reports the application that owns the current clipboard, for the exclusion check and for the
	// event's attribution. nil or "" = attribution unavailable on this display server.
	Source func() string

	haveLast bool
	last     [32]byte
}

// Poll reads the clipboard once. It returns the content and true when the content CHANGED since the previous
// call; otherwise (nil, false, nil). An empty clipboard is treated as content like any other, so clearing
// the clipboard is a change but does not report bytes.
func (w *Watcher) Poll(ctx context.Context) ([]byte, bool, error) {
	// Exclusions FIRST: the whole value of this control is that an excluded application's copy is never
	// read. Reading it and discarding the classification would still have pulled the secret in here.
	if w.Exclusions != nil && w.Source != nil {
		if src := w.Source(); w.Exclusions.Excluded(src) {
			return nil, false, nil
		}
	}
	b, err := w.Reader.Read(ctx)
	if err != nil {
		return nil, false, err
	}
	d := Digest(b)
	if w.haveLast && d == w.last {
		return nil, false, nil
	}
	w.haveLast = true
	w.last = d
	if len(b) == 0 {
		return nil, false, nil // a cleared clipboard is a change with nothing to classify
	}
	return b, true, nil
}
