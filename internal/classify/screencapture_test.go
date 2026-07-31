package classify

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// screenPNG renders a flat 1920x1080 image — a captured screen's two properties, an exact display
// resolution and a small palette over large flat areas.
func screenPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 1920, 1080))
	bg := color.RGBA{0xf5, 0xf5, 0xf5, 0xff}
	fg := color.RGBA{0x22, 0x22, 0x22, 0xff}
	for y := 0; y < 1080; y++ {
		for x := 0; x < 1920; x++ {
			c := bg
			if (y/12)%3 == 0 && (x/7)%2 == 0 {
				c = fg
			}
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func hitFor(hits []*corev1.DetectorHit, want corev1.DetectorType) *corev1.DetectorHit {
	for _, h := range hits {
		if h.GetDetectorType() == want {
			return h
		}
	}
	return nil
}

// A SCREENSHOT REACHES THE PIPELINE AS A CLASSIFICATION HIT.
//
// The detector has its own tests; this one is about the WIRING, which is where this kind of feature
// usually dies — a package with tests and no caller. It proves the classifier the worker actually runs
// produces a hit for image content, so a policy can be written against it.
func TestAScreenCaptureIsClassifiedByTheWorkersClassifier(t *testing.T) {
	c := New()
	hits, err := c.Classify(context.Background(), bytes.NewReader(screenPNG(t)))
	if err != nil {
		t.Fatalf("classifying a PNG: %v", err)
	}
	h := hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_SCREEN_CAPTURE)
	if h == nil {
		t.Fatalf("a captured screen produced no SCREEN_CAPTURE hit (%d hits). A screenshot of a "+
			"spreadsheet then reaches policy looking exactly like an ordinary picture", len(hits))
	}
	if h.GetConfidence() <= 0 || h.GetConfidence() > 1 {
		t.Errorf("confidence %v is outside [0,1]", h.GetConfidence())
	}
}

// ORDINARY CONTENT DOES NOT PRODUCE THE HIT.
//
// Without this the test above passes for a classifier that emits SCREEN_CAPTURE for everything, and the
// signal would be worthless the moment anyone wrote a policy against it.
func TestOrdinaryContentDoesNotLookLikeAScreenCapture(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"plain text", []byte("a perfectly ordinary memo about lunch")},
		{"a document with PII", []byte("CPF 111.444.777-35 and an email at user@example.com")},
		{"empty", nil},
	} {
		hits, err := New().Classify(context.Background(), bytes.NewReader(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if h := hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_SCREEN_CAPTURE); h != nil {
			t.Errorf("%s was reported as a screen capture", tc.name)
		}
	}
}

// THE TEXT DETECTORS STILL RUN OVER IMAGE CONTENT.
//
// The screen-capture check happens before extraction and must not short-circuit anything: an image is
// still scanned by every other detector, so a PNG with a card number in its metadata is not made
// invisible by having been recognised as a screenshot.
func TestRecognisingAScreenCaptureDoesNotSuppressTheOtherDetectors(t *testing.T) {
	shot := screenPNG(t)
	withPII := append(shot, []byte("CPF 111.444.777-35")...)

	hits, err := New().Classify(context.Background(), bytes.NewReader(withPII))
	if err != nil {
		t.Fatal(err)
	}
	if hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_SCREEN_CAPTURE) == nil {
		t.Fatal("the screen capture was not recognised, so this test is not exercising its case")
	}
	if hitFor(hits, corev1.DetectorType_DETECTOR_TYPE_CPF) == nil {
		t.Fatal("a CPF in the same content was MISSED once the content was recognised as a screen " +
			"capture. One detector must never silence another — that turns a recognised carrier into a " +
			"way to hide a payload")
	}
}
