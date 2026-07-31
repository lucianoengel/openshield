//go:build integration

package integration

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAScreenshotOfADocumentIsRecognisedByTheShippedEngine is DLP-9 end to end.
//
// A screenshot of a spreadsheet is a document that walks past every text detector this product has: the
// bytes are a PNG, and the sensitive content is pixels that happen to look like characters. It is one of
// the most common deliberate-exfil moves there is, and until this shipped OpenShield could not see it.
//
// The scenario drives the real binaries — a file lands in a watched directory, the engine's sandboxed
// worker classifies it, and a policy written against the signal produces a decision. What it proves is
// the WIRING: the detector has its own tests, but a detector with no caller is the failure mode this
// project's own guards exist to catch.
const screenCapturePolicy = `package openshield
import rego.v1
capture if { some h in input.classification; h.type == "DETECTOR_TYPE_SCREEN_CAPTURE" }
decision := {"action":"ALERT","reason":"a captured screen is leaving"} if { capture }
decision := {"action":"ALLOW","reason":"not a capture"} if { not capture }`

// renderScreen writes a PNG with the two properties of a captured screen: an exact display resolution and
// a small palette over large flat areas. A photograph has neither.
func renderScreen(t *testing.T, path string, w, h int, flat bool) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	bg := color.RGBA{0xf0, 0xf0, 0xf0, 0xff}
	fg := color.RGBA{0x20, 0x20, 0x20, 0xff}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var c color.RGBA
			switch {
			case !flat:
				// Busy content: every pixel a different value, as a sensor produces.
				c = color.RGBA{uint8(x * 7), uint8(y * 11), uint8(x*3 + y*5), 0xff}
			case (y/12)%3 == 0 && (x/7)%2 == 0:
				c = fg
			default:
				c = bg
			}
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAScreenshotOfADocumentIsRecognisedByTheShippedEngine(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()

	policy := filepath.Join(work, "capture.rego")
	if err := os.WriteFile(policy, []byte(screenCapturePolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	pool := openPool(t, stack.DSN)
	alerts := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A BUSY IMAGE FIRST, at the same dimensions. If this alerted, the assertion below would prove only
	// that images produce alerts — not that a CAPTURE does.
	renderScreen(t, filepath.Join(watch, "photo.png"), 1920, 1080, false)
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("%d alerts for a busy image at screen dimensions. The signal fires on ordinary "+
			"pictures, which is a detector an operator turns off within a day", n)
	}

	// Now the capture.
	renderScreen(t, filepath.Join(watch, "capture.png"), 1920, 1080, true)
	Eventually(t, 90*time.Second, "the captured screen to be recognised and alerted", func() bool {
		return alerts() > 0
	})
}
