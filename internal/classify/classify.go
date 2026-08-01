// Package classify is the endpoint pattern classifier: format-plus-checksum
// detection for the PII types the schema names (D5, D10).
//
// It runs in the unprivileged worker, on attacker-influenced bytes. Two
// properties are load-bearing and enforced by test, not by discipline:
//
//   - It emits type + confidence + count ONLY. Matched content never leaves
//     this package; a DetectorHit has no field that could carry it. For
//     low-entropy PII a hash IS the value (D10), and a similarity-preserving
//     fingerprint reconstructs the input (D11), so neither is emitted either.
//   - It matches with RE2 (Go's regexp), which is linear-time. A backtracking
//     engine on hostile input is a denial-of-service and, because slow
//     classification fails open (D17), a Block-to-Allow bypass.
//
// Confidence is never 1.0. Classification is probabilistic; a policy that reads
// it as certainty is the mistake D4 exists to prevent.
package classify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/screenshot"
)

// Detector matches one PII type. Scan returns the number of VALID matches and
// the confidence to report for that type; a count of 0 means no hit.
type Detector interface {
	Type() corev1.DetectorType
	Scan(text []byte) (count int, confidence float64)
}

// Classifier runs a fixed registry of detectors and returns their hits.
type Classifier struct {
	detectors []Detector
}

// New returns the default classifier: CPF, credit card, SSN, email, and the
// Phase-D2 secrets detectors (private keys, AWS keys, JWTs, vendor API tokens).
func New() *Classifier {
	return &Classifier{detectors: []Detector{
		cpf{}, creditCard{}, ssn{}, email{}, phone{},
		privateKey{}, awsAccessKey{}, jwt{}, apiToken{},
		iban{}, healthData{}, abaRouting{}, caSIN{}, npi{}, ukNHS{}, ein{},
		passport{}, driversLicense{}, // DLP-7: context-gated weak-format identifiers
		aadhaar{}, ukNINO{}, // DLP-7: India Aadhaar (Verhoeff) + UK NINO (context-gated)
		esDNI{}, frNIR{}, // DLP-10: Spain DNI/NIE (context-gated) + France NIR (mod 97)
	}}
}

// AddEDM adds an EDM detector over the given fingerprint index (DLP-3) to this
// classifier, so exact-data matching composes with the built-in and custom
// detectors. A nil/empty index is a no-op — EDM runs only when configured.
func (c *Classifier) AddEDM(index *EDMIndex) {
	if index != nil && index.Size() > 0 {
		c.detectors = append(c.detectors, edm{index: index})
	}
}

// Classify reads the (worker-bounded) stream fully and runs every detector.
//
// A read error is returned as an error, never as an empty result: empty hits
// mean "scanned, found nothing", an error means "did not scan", and conflating
// them would let a file that crashes the reader read as clean.
func (c *Classifier) Classify(_ context.Context, r io.Reader) ([]*corev1.DetectorHit, error) {
	text, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("classify: reading input: %w", err)
	}
	// Phase D1 + DLP-8: if the bytes are a structured document (OOXML/PDF) or an ARCHIVE, extract the
	// text first — otherwise the detectors scan compressed noise and miss PII inside a .docx/.pdf or a
	// file placed in a .zip (even nested). extractContent recurses archive members (bounded by a shared
	// byte budget + depth). A non-container (or one that fails to parse) is scanned as-is, so a
	// mis-detection degrades to "scan raw", never "scan nothing".
	var hits []*corev1.DetectorHit
	// DLP-9: a screenshot of a spreadsheet is a document that walks past every detector below it — the
	// bytes are a PNG, and the sensitive content is pixels that happen to look like characters. This runs
	// on the ORIGINAL bytes, before extraction, because the image IS the content rather than a container
	// holding some.
	//
	// It reports that the content has the SHAPE of a captured screen; it does not read the text (that
	// means OCR, and every general OCR engine is a large native image parser — the class D13/D72 exist to
	// contain). A hit says a screen was captured, never what was on it.
	if hit := screenCaptureHit(text); hit != nil {
		hits = append(hits, hit)
	}

	budget := int64(maxExtractBytes)
	text = extractContent(text, 0, &budget)
	for _, d := range c.detectors {
		count, conf := d.Scan(text)
		if count == 0 {
			continue
		}
		hits = append(hits, &corev1.DetectorHit{
			DetectorType: d.Type(),
			Confidence:   conf,
			Count:        uint32(count),
		})
	}
	return hits, nil
}

// countValid runs a candidate regex, applies a validator to the normalized form
// of each candidate, and counts distinct valid values. The normalized-value set
// lives only for this call and is never emitted — de-duplication so a repeated
// fixture does not inflate the count, without exposing the values themselves.
func countValid(re *regexp.Regexp, text []byte, normalize func([]byte) string, valid func(string) bool) int {
	seen := map[string]struct{}{}
	for _, m := range re.FindAll(text, -1) {
		n := normalize(m)
		if !valid(n) {
			continue
		}
		seen[n] = struct{}{}
	}
	return len(seen)
}

// stripNonDigits keeps only ASCII digits — the normalized form for the numeric
// detectors.
func stripNonDigits(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return string(out)
}

// imageMagic are the leading bytes of the formats Go's standard library decodes here.
//
// The sniff exists so ordinary text is never handed to an image decoder, and so a FAILURE to decode
// something that really is an image is distinguishable from content that was never an image at all.
var imageMagic = [][]byte{
	{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, // PNG
	{0xff, 0xd8, 0xff},                            // JPEG
	{'G', 'I', 'F', '8'},                          // GIF
}

// screenCaptureHit analyses image content and returns a hit when it looks like a captured screen.
//
// A CORRUPT IMAGE YIELDS NO SIGNAL, and that is a stated limit rather than a claim of cleanliness: the
// text detectors still run over the same bytes, and ClassifyResponse carries one error field for the
// whole classification, so failing everything because one image would not decode would turn a damaged
// attachment into an unscannable file. What is NOT done here is pretending it was examined.
func screenCaptureHit(content []byte) *corev1.DetectorHit {
	isImage := false
	for _, m := range imageMagic {
		if bytes.HasPrefix(content, m) {
			isImage = true
			break
		}
	}
	if !isImage {
		return nil
	}
	a, err := screenshot.Analyze(content)
	if err != nil || !a.Likely() {
		return nil
	}
	return &corev1.DetectorHit{
		DetectorType: corev1.DetectorType_DETECTOR_TYPE_SCREEN_CAPTURE,
		Confidence:   a.Score,
		Count:        1,
	}
}
