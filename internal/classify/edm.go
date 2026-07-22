package classify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// EDMIndex is a k-anonymized fingerprint index of an operator's sensitive values:
// a bloom filter that stores ONLY hashes, never the raw values, with a bounded,
// computable false-positive rate. That is what lets the index ship into the
// sandboxed worker (or an endpoint) without the sensitive dataset leaving the
// operator (ADR-9, D10/D11).
type EDMIndex struct {
	bits []uint64 // bit array, m = len(bits)*64
	m    uint64   // number of bits
	k    uint64   // number of probes
	n    uint64   // values added
}

// NewEDMIndex sizes a bloom filter for n values at a target false-positive rate.
// m = -n*ln(p)/(ln2)^2, k = (m/n)*ln2 — the standard optimal parameters.
func NewEDMIndex(targetFP float64, n int) *EDMIndex {
	if n < 1 {
		n = 1
	}
	if targetFP <= 0 || targetFP >= 1 {
		targetFP = 0.001
	}
	m := uint64(math.Ceil(-float64(n) * math.Log(targetFP) / (math.Ln2 * math.Ln2)))
	// Floor m well above the probe count so even a tiny index is a SPARSE filter —
	// a small m with many probes is degenerate (probes collide, and the effective
	// FP for the many windows a scan generates balloons).
	if m < 512 {
		m = 512
	}
	k := uint64(math.Round(float64(m) / float64(n) * math.Ln2))
	if k < 1 {
		k = 1
	}
	// Cap k: beyond ~16 probes the marginal FP gain is negligible and over-probing a
	// small filter is actively harmful.
	if k > 16 {
		k = 16
	}
	return &EDMIndex{bits: make([]uint64, (m+63)/64), m: m, k: k}
}

// probes returns the k bit positions for a normalized value, via double hashing
// (two 32-bit halves of one SHA-256): h_i = (h1 + i*h2) mod m.
func (x *EDMIndex) probes(value string) []uint64 {
	sum := sha256.Sum256([]byte(value))
	h1 := binary.BigEndian.Uint64(sum[0:8])
	h2 := binary.BigEndian.Uint64(sum[8:16])
	out := make([]uint64, x.k)
	for i := uint64(0); i < x.k; i++ {
		out[i] = (h1 + i*h2) % x.m
	}
	return out
}

func (x *EDMIndex) set(pos uint64)      { x.bits[pos/64] |= 1 << (pos % 64) }
func (x *EDMIndex) get(pos uint64) bool { return x.bits[pos/64]&(1<<(pos%64)) != 0 }

// Add inserts a value's fingerprint (after normalization).
func (x *EDMIndex) Add(value string) {
	v := normalizeEDM(value)
	if v == "" {
		return
	}
	for _, p := range x.probes(v) {
		x.set(p)
	}
	x.n++
}

// Contains reports whether a value is (probably) in the index. A false result is
// definitive; a true result is correct up to the bloom false-positive rate.
func (x *EDMIndex) Contains(value string) bool {
	v := normalizeEDM(value)
	if v == "" {
		return false
	}
	for _, p := range x.probes(v) {
		if !x.get(p) {
			return false
		}
	}
	return true
}

// EstimatedFP is the current false-positive probability, (1 - e^(-k*n/m))^k.
func (x *EDMIndex) EstimatedFP() float64 {
	if x.n == 0 {
		return 0
	}
	return math.Pow(1-math.Exp(-float64(x.k)*float64(x.n)/float64(x.m)), float64(x.k))
}

// Size reports the number of values indexed.
func (x *EDMIndex) Size() int { return int(x.n) }

// normalizeEDM lowercases and strips non-alphanumerics so a value matches across
// formatting (1234-5678 == 1234 5678), applied at both build and scan time.
func normalizeEDM(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MinEDMTokenLen is the shortest normalized token the builder will index — shorter
// tokens are low-entropy and would over-match (a column of first names indexing
// "john" flags every flow mentioning John).
const MinEDMTokenLen = 6

// BuildEDMIndex builds an index from sensitive values at the target FP rate,
// skipping low-entropy tokens (below MinEDMTokenLen, or purely-alphabetic short
// dictionary shapes). It returns the index and the number of values SKIPPED (never
// silently dropped — the operator sees how much of the dataset was too generic).
func BuildEDMIndex(values []string, targetFP float64) (*EDMIndex, int) {
	idx := NewEDMIndex(targetFP, len(values))
	skipped := 0
	for _, v := range values {
		if !distinctiveEDM(v) {
			skipped++
			continue
		}
		idx.Add(v)
	}
	return idx, skipped
}

// distinctiveEDM reports whether a value is distinctive enough to index: at least
// MinEDMTokenLen normalized chars, and not a short purely-alphabetic token (a
// likely dictionary word). A value with digits is always kept (an identifier).
func distinctiveEDM(v string) bool {
	n := normalizeEDM(v)
	if len(n) < MinEDMTokenLen {
		return false
	}
	hasDigit := false
	for _, r := range n {
		if unicode.IsDigit(r) {
			hasDigit = true
			break
		}
	}
	// Purely-alphabetic and short-ish → treat as a dictionary word (skip). A long
	// alphabetic value (a full name run, a long code) is kept.
	if !hasDigit && len(n) < MinEDMTokenLen+4 {
		return false
	}
	return true
}

// Marshal serializes the index (params + bloom bits) — never any raw value, since
// the index only ever held hashes.
func (x *EDMIndex) Marshal() []byte {
	out := make([]byte, 0, 32+len(x.bits)*8)
	var hdr [32]byte
	binary.BigEndian.PutUint64(hdr[0:8], x.m)
	binary.BigEndian.PutUint64(hdr[8:16], x.k)
	binary.BigEndian.PutUint64(hdr[16:24], x.n)
	binary.BigEndian.PutUint64(hdr[24:32], uint64(len(x.bits)))
	out = append(out, hdr[:]...)
	for _, w := range x.bits {
		var wb [8]byte
		binary.BigEndian.PutUint64(wb[:], w)
		out = append(out, wb[:]...)
	}
	return out
}

// LoadEDMIndex reconstructs an index from Marshal bytes.
func LoadEDMIndex(b []byte) (*EDMIndex, error) {
	if len(b) < 32 {
		return nil, fmt.Errorf("classify: EDM index too short")
	}
	m := binary.BigEndian.Uint64(b[0:8])
	k := binary.BigEndian.Uint64(b[8:16])
	n := binary.BigEndian.Uint64(b[16:24])
	words := binary.BigEndian.Uint64(b[24:32])
	if uint64(len(b)) != 32+words*8 {
		return nil, fmt.Errorf("classify: EDM index length mismatch")
	}
	if m == 0 || k == 0 {
		return nil, fmt.Errorf("classify: EDM index has zero m or k")
	}
	bits := make([]uint64, words)
	for i := uint64(0); i < words; i++ {
		bits[i] = binary.BigEndian.Uint64(b[32+i*8 : 40+i*8])
	}
	return &EDMIndex{bits: bits, m: m, k: k, n: n}, nil
}

// edm is the EDM detector: it tokenizes content and counts values present in the
// index. It reports DETECTOR_TYPE_EDM — a specific-record match, distinct from a
// format hit.
type edm struct{ index *EDMIndex }

func (edm) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_EDM }

// MaxEDMSpan is how many adjacent tokens a single indexed value may span in
// content. A value written "1234-5678-9012" normalizes to one fingerprint, but in a
// flow it can appear as "1234 5678 9012" — three tokens. Matching windows of up to
// MaxEDMSpan adjacent tokens (joined after normalization) reconstructs the
// separator-stripped value and finds it.
const MaxEDMSpan = 4

// Scan slides windows of 1..MaxEDMSpan adjacent tokens, joins each window's
// normalized parts (reconstructing the separator-stripped value), and counts the
// DISTINCT windows present in the index. Confidence reflects the bloom FP rate (a
// bloom hit is probabilistic), capped strictly below 1.0.
func (d edm) Scan(text []byte) (int, float64) {
	if d.index == nil || d.index.Size() == 0 {
		return 0, 0
	}
	toks := strings.FieldsFunc(string(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	norm := make([]string, len(toks))
	for i, tk := range toks {
		norm[i] = normalizeEDM(tk)
	}

	seen := map[string]struct{}{}
	count := 0
	for i := range norm {
		var window strings.Builder
		for span := 0; span < MaxEDMSpan && i+span < len(norm); span++ {
			window.WriteString(norm[i+span])
			w := window.String()
			if len(w) < MinEDMTokenLen {
				continue
			}
			if _, dup := seen[w]; dup {
				continue
			}
			if d.index.Contains(w) {
				seen[w] = struct{}{}
				count++
			}
		}
	}
	if count == 0 {
		return 0, 0
	}
	conf := 1 - d.index.EstimatedFP()
	if conf > 0.99 {
		conf = 0.99
	}
	return count, conf
}
