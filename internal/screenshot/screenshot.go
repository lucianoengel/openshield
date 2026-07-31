// Package screenshot recognises an image as a CAPTURED SCREEN rather than a photograph (DLP-9).
//
// A screenshot of a spreadsheet is a document that walks past every text detector this product has. The
// bytes are a PNG; there is no CPF in them, no card number, no keyword — the sensitive content is pixels
// that happen to look like characters. It is one of the most common deliberate-exfil moves there is, and
// until now OpenShield could not see it at all.
//
// THIS DOES NOT READ THE TEXT, AND THAT IS THE WHOLE DESIGN. Reading it means OCR, and every general OCR
// engine is a large native image parser — the exact class D13/D72 exist to contain. What this reports is
// that a piece of content HAS THE SHAPE OF A CAPTURED SCREEN, so a policy can act on "an image that looks
// like a captured document is leaving, from a user whose recent activity is X". It is a signal about the
// carrier, not a classification of the payload, and it must never be described as the latter: it cannot
// tell a recipe from a customer list.
//
// THE DECODER IS GO'S OWN. image/png and image/jpeg are memory-safe and continuously fuzzed upstream by
// the Go project, so the dangerous half of image handling — parsing attacker-controlled image formats in
// C — simply is not present. This still runs in the sandboxed worker (D72), because it is content.
package screenshot

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// maxPixels bounds what will be decoded.
//
// A DECOMPRESSION BOMB IS THE FIRST THING AN IMAGE PARSER MEETS: a few hundred bytes of PNG can declare a
// 60000x60000 canvas, and decoding it allocates gigabytes before any analysis happens. The header is read
// FIRST (DecodeConfig reads dimensions without decoding pixels) and an over-budget image is refused
// unexamined. 64 megapixels is far beyond any real screen and far below what hurts.
const maxPixels = 64 << 20

// maxSamples bounds the pixel walk. Colour diversity is a statistical property; sampling a bounded number
// of pixels answers it as well as reading forty million of them, and in constant time.
const maxSamples = 100000

// ErrTooLarge is returned for an image whose declared dimensions exceed the budget.
var ErrTooLarge = errors.New("screenshot: declared image dimensions exceed the decode budget")

// Analysis is the content-free result. It carries dimensions and derived ratios — never pixels, never a
// thumbnail, never anything from which the image could be reconstructed (D10/D29).
type Analysis struct {
	Format string
	Width  int
	Height int

	// ScreenSized reports that the dimensions exactly match a known display resolution. It is the
	// strongest single signal and the hardest to produce by accident: a photograph is whatever the
	// sensor is, and a cropped image is almost never exactly 1920x1080.
	ScreenSized bool

	// FlatColor is the fraction of sampled pixels that were NOT distinct colours. Rendered text and UI
	// use a handful of colours over large flat areas; a photograph is nearly all distinct values. High
	// means "looks rendered".
	FlatColor float64

	// Score is the composite in [0,1].
	Score float64
}

// Threshold is the score at or above which content is reported as a likely screen capture.
//
// It is a NAMED CONSTANT rather than a number inside the comparison so a test can state the boundary it
// is asserting instead of rediscovering it, and so an operator reading a finding can see what it took.
const Threshold = 0.6

// Likely reports whether this analysis crosses the threshold.
func (a Analysis) Likely() bool { return a.Score >= Threshold }

// displayModes are exact resolutions produced by capturing a whole screen.
//
// The list is deliberately EXACT-MATCH and deliberately short. A "close enough" rule (within N pixels, or
// a 16:9 ratio) would match a large share of ordinary photographs, and a signal that fires on holiday
// pictures is one an operator turns off — the same failure the JIT allowlist exists to prevent one row
// up in the capability table.
var displayModes = [][2]int{
	{1280, 720}, {1280, 800}, {1366, 768}, {1440, 900}, {1600, 900}, {1680, 1050},
	{1920, 1080}, {1920, 1200}, {2048, 1152}, {2256, 1504}, {2560, 1080}, {2560, 1440},
	{2560, 1600}, {2880, 1800}, {3072, 1920}, {3440, 1440}, {3840, 2160}, {5120, 2880},
	{1170, 2532}, {1179, 2556}, {1284, 2778}, {1290, 2796}, // phones, in their own orientation
}

// screenSized reports an exact match in either orientation.
func screenSized(w, h int) bool {
	for _, m := range displayModes {
		if (w == m[0] && h == m[1]) || (w == m[1] && h == m[0]) {
			return true
		}
	}
	return false
}

// Analyze decodes an image and reports whether it looks like a captured screen.
//
// A decode failure is an ERROR, never a zero Analysis. "Not a screenshot" and "could not look" are
// opposite answers, and conflating them is the defect this project keeps finding: a crashing parser would
// read as clean content (the same reason ClassifyResponse carries an error field distinct from an empty
// hit list).
func Analyze(b []byte) (Analysis, error) {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return Analysis{}, fmt.Errorf("screenshot: reading the image header: %w", err)
	}
	// BOUND BEFORE DECODING. The header is attacker-controlled and cheap; the decode it authorises is not.
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxPixels {
		return Analysis{Format: format, Width: cfg.Width, Height: cfg.Height},
			fmt.Errorf("%w: %dx%d", ErrTooLarge, cfg.Width, cfg.Height)
	}

	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return Analysis{Format: format}, fmt.Errorf("screenshot: decoding: %w", err)
	}

	a := Analysis{Format: format, Width: cfg.Width, Height: cfg.Height}
	a.ScreenSized = screenSized(a.Width, a.Height)
	a.FlatColor = flatColorRatio(img)
	a.Score = score(a)
	return a, nil
}

// flatColorRatio samples the image and reports the fraction of samples that repeated a colour already
// seen. Rendered text and UI reuse a small palette over large flat areas; a photograph almost never does.
func flatColorRatio(img image.Image) float64 {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w <= 0 || h <= 0 {
		return 0
	}
	total := w * h
	step := 1
	if total > maxSamples {
		step = total / maxSamples
	}
	seen := make(map[uint64]struct{}, maxSamples)
	samples, repeats := 0, 0
	for i := 0; i < total; i += step {
		x, y := bounds.Min.X+i%w, bounds.Min.Y+i/w
		if y >= bounds.Max.Y {
			break
		}
		r, g, bl, _ := img.At(x, y).RGBA()
		// 8 bits per channel: a photograph's sensor noise makes neighbouring pixels differ in the low
		// bits, and counting those as distinct colours is the point.
		key := uint64(r>>8)<<16 | uint64(g>>8)<<8 | uint64(bl>>8)
		if _, ok := seen[key]; ok {
			repeats++
		} else {
			seen[key] = struct{}{}
		}
		samples++
	}
	if samples == 0 {
		return 0
	}
	return float64(repeats) / float64(samples)
}

// flatKnee is where "flat enough to be rendered" begins.
//
// It is not tuned to a fixture. The two populations are nowhere near it: content rendered from a palette
// repeats colours on essentially every sampled pixel (measured ~0.999 for a UI with a background, a text
// colour and some chrome), while an image with sensor-style noise repeats on a fifth of them (~0.2). The
// knee sits in the empty space between, which is what makes it a boundary rather than a tuning knob.
const flatKnee = 0.8

// score combines the signals.
//
// A PRODUCT, NOT A SUM, and the first version of this file got it wrong in a way its own tests caught: a
// floor for being screen-sized meant a NOISY image at exactly 1920x1080 scored 0.609 and was reported,
// and a flat 300x200 logo scored 1.000. Either alone convicts nothing now — both have ordinary
// explanations, and a signal that fires on holiday photographs and icons is one an operator turns off.
//
// THE HONEST LIMIT: a capture that is not exactly a display resolution — a window crop, a region
// selection — cannot reach the threshold, because flatness alone is what charts, diagrams and logos look
// like. This detects FULL-SCREEN captures. Recognising a cropped one needs a signal this does not have,
// and claiming otherwise would be worse than the gap.
func score(a Analysis) float64 {
	// Flatness, with everything below the knee contributing nothing at all.
	flat := (a.FlatColor - flatKnee) / (1 - flatKnee)
	if flat < 0 {
		flat = 0
	}
	if flat > 1 {
		flat = 1
	}
	size := 0.5
	if a.ScreenSized {
		size = 1
	}
	return size * flat
}
