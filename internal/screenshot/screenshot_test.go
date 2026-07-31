package screenshot

import (
	"bytes"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"reflect"
	"testing"
)

// THE FIXTURES ARE BUILT, NOT BORROWED, and they are built to be honestly different.
//
// A rendered screen is a small palette over large flat areas: a background, a text colour, some chrome.
// A photograph is sensor noise — neighbouring pixels differ in their low bits almost everywhere. Those
// are the two populations this detector has to separate, and generating them here means the test does not
// depend on a binary fixture nobody can inspect in review.
//
// Stated plainly: synthetic noise is not a photograph, and passing this is not evidence of a real-world
// false-positive rate. It is evidence that the signal separates flat rendered content from busy content,
// which is the mechanism. The false-positive question is answered by running it on a real corpus, and
// that is not something a unit test can stand in for.

func renderedScreen(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	bg := color.RGBA{0xf5, 0xf5, 0xf5, 0xff}
	fg := color.RGBA{0x22, 0x22, 0x22, 0xff}
	chrome := color.RGBA{0x30, 0x60, 0xc0, 0xff}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := bg
			if y < h/20 {
				c = chrome // a title bar
			} else if (y/12)%3 == 0 && x > w/10 && x < w*9/10 && (x/7)%2 == 0 {
				c = fg // rows of text-like marks
			}
			img.Set(x, y, c)
		}
	}
	return encode(t, img)
}

func photograph(t *testing.T, w, h int) []byte {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// A smooth gradient plus per-pixel noise: what a sensor produces, and the opposite of a
			// palette.
			base := uint8((x*255)/w/2 + (y*255)/h/2)
			img.Set(x, y, color.RGBA{
				base + uint8(rng.Intn(24)),
				base/2 + uint8(rng.Intn(24)),
				255 - base + uint8(rng.Intn(24)),
				0xff,
			})
		}
	}
	return encode(t, img)
}

func encode(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// THE HEADLINE: a full-screen capture is recognised, and a photograph of the same size is not.
//
// Both are tested TOGETHER and at the SAME dimensions, because separately each is worthless. "The
// screenshot scored high" passes for a detector that returns 1.0 for everything; "the photo scored low"
// passes for one that returns 0. The claim is that it SEPARATES them, so the test has to be the
// comparison.
func TestACapturedScreenIsDistinguishedFromAPhotographOfTheSameSize(t *testing.T) {
	shot, err := Analyze(renderedScreen(t, 1920, 1080))
	if err != nil {
		t.Fatal(err)
	}
	photo, err := Analyze(photograph(t, 1920, 1080))
	if err != nil {
		t.Fatal(err)
	}

	if !shot.Likely() {
		t.Errorf("a rendered 1920x1080 screen scored %.3f, below the %.2f threshold — a screenshot of a "+
			"spreadsheet is a document that walks past every text detector this product has, and this is "+
			"the only thing that sees it", shot.Score, Threshold)
	}
	if photo.Likely() {
		t.Errorf("a PHOTOGRAPH at exactly 1920x1080 scored %.3f and was reported as a screen capture. A "+
			"signal that fires on holiday pictures is one the operator turns off, and then it protects "+
			"nothing at all", photo.Score)
	}
	if shot.Score <= photo.Score {
		t.Fatalf("the detector does not separate them at all (screen %.3f, photo %.3f)",
			shot.Score, photo.Score)
	}
}

// EXACT DIMENSIONS ARE NOT ENOUGH ON THEIR OWN.
//
// The composition is a product rather than a sum precisely so one signal cannot carry a verdict. A photo
// cropped to exactly 1920x1080 is unusual but it happens, and it must not be enough by itself.
//
// Mutation (score = 1.0 whenever ScreenSized): the photograph above is reported → FAIL, verified.
func TestBeingScreenSizedAloneDoesNotConvict(t *testing.T) {
	photo, err := Analyze(photograph(t, 1920, 1080))
	if err != nil {
		t.Fatal(err)
	}
	if photo.ScreenSized != true {
		t.Fatal("the fixture is not screen-sized, so this test is not exercising the case it names")
	}
	if photo.Likely() {
		t.Fatalf("an exactly screen-sized image was convicted on its dimensions alone (score %.3f)",
			photo.Score)
	}
}

// AND NEITHER IS FLATNESS ALONE, at an unremarkable size.
//
// A logo, a chart or a diagram is flat-coloured and is not a captured screen. Without this the detector
// would report every icon that crosses the wire.
func TestAFlatImageAtAnOrdinarySizeIsNotAScreenCapture(t *testing.T) {
	logo, err := Analyze(renderedScreen(t, 300, 200))
	if err != nil {
		t.Fatal(err)
	}
	if logo.ScreenSized {
		t.Fatal("300x200 was treated as a display resolution")
	}
	if logo.Likely() {
		t.Fatalf("a small flat image — a logo or a chart — was reported as a screen capture (score "+
			"%.3f). This detector would then fire on ordinary graphics all day", logo.Score)
	}
}

// A DECOMPRESSION BOMB IS REFUSED BEFORE IT IS DECODED.
//
// A few hundred bytes of PNG can declare an enormous canvas; decoding it allocates gigabytes inside the
// worker before any analysis begins. The header is read first and an over-budget image is refused
// unexamined — the same discipline the archive extractor already applies.
//
// Mutation (check the budget after Decode instead of after DecodeConfig): the allocation happens anyway
// and the sandbox's memory limit kills the worker instead of the image being refused.
func TestAnOversizedImageIsRefusedWithoutBeingDecoded(t *testing.T) {
	// A VALID PNG header declaring 60000x60000, with no pixel data behind it.
	//
	// The CRC has to be real. With a bad one the decoder rejects the file on its checksum and the test
	// passes for a reason that has nothing to do with the size budget — which is exactly what the first
	// version of this fixture did.
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	body := []byte{'I', 'H', 'D', 'R',
		0, 0, 0xEA, 0x60, 0, 0, 0xEA, 0x60, // 60000 x 60000 = 3.6 gigapixels
		8, 2, 0, 0, 0} // 8-bit RGB
	buf.Write([]byte{0, 0, 0, 13})
	buf.Write(body)
	crc := crc32.ChecksumIEEE(body)
	buf.Write([]byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)})

	_, err := Analyze(buf.Bytes())
	if err == nil {
		t.Fatal("a 60000x60000 image was accepted. Decoding it allocates gigabytes in the sandboxed " +
			"worker, so the bound has to be applied to the declared dimensions, before the decode")
	}
	// IT MUST BE REFUSED BY THE BOUND, not by the decoder failing for some other reason.
	//
	// The first version of this test asserted only that SOMETHING went wrong, and it passed with the
	// bound deleted — this fixture has no pixel data, so the decoder errors either way. That made the
	// test agree with a build that would have happily decoded a real bomb. Naming the error is what
	// separates "refused unexamined" from "tried and failed".
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("refused with %v, not the size bound. The image was rejected by the DECODER rather than "+
			"by the budget, so a well-formed bomb of the same dimensions would be decoded in full", err)
	}
}

// CONTENT THAT IS NOT AN IMAGE IS AN ERROR, never a confident "no".
//
// "Not a screenshot" and "could not look" are opposite answers. A parser that failed and reported clean
// is the defect this codebase keeps finding — it is why ClassifyResponse carries an error field distinct
// from an empty hit list.
func TestNonImageContentIsAnErrorRatherThanAConfidentNo(t *testing.T) {
	a, err := Analyze([]byte("this is a text file, not an image at all"))
	if err == nil {
		t.Fatal("arbitrary bytes were analysed as an image")
	}
	if a.Likely() {
		t.Fatal("a failed decode produced a positive verdict")
	}
	if a.Score != 0 {
		t.Fatalf("a failed decode produced a score of %.3f — an unreadable image must not carry a "+
			"number that a policy could act on", a.Score)
	}
}

// THE RESULT CARRIES NO PIXELS.
//
// This runs on content, and its output crosses the worker boundary (D10/D29). Dimensions and ratios are
// derived facts; anything from which the image could be reconstructed is not, and a struct is the easiest
// place for that to go wrong later without anyone noticing. So the guard is REFLECTIVE: it fails when a
// field of a content-carrying kind appears, whatever it is called.
func TestTheAnalysisCarriesNothingFromWhichTheImageCouldBeRebuilt(t *testing.T) {
	ty := reflect.TypeOf(Analysis{})
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		switch f.Type.Kind() {
		case reflect.Bool, reflect.Int, reflect.Float64:
			// derived scalars — fine
		case reflect.String:
			// Only the format name, which is a fixed vocabulary rather than anything from the image.
			if f.Name != "Format" {
				t.Errorf("Analysis.%s is a string. A string on this struct crosses the worker boundary; "+
					"unless it is a fixed vocabulary like the format name, it is content", f.Name)
			}
		default:
			t.Errorf("Analysis.%s is a %s. Slices, maps and image types can carry the picture itself "+
				"across the boundary the worker exists to hold (D10/D29) — this result must be derived "+
				"facts only", f.Name, f.Type.Kind())
		}
	}
}
