package classify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// DefaultShingleK is the default number of words per shingle. Long enough that a
// shingle is high-entropy (not brute-forceable, boilerplate rarely collides), short
// enough that a modest excerpt still yields several shingles.
const DefaultShingleK = 5

// DocumentIndex fingerprints sensitive DOCUMENTS as the hashes of their overlapping
// word k-gram shingles (IDM, DLP-3): the unstructured-document counterpart to EDM.
// It maps each shingle fingerprint to the documents containing it, so the scanner can
// tell how much of a fingerprinted document appears in content, and fires on a
// FRACTION of a document's shingles. Stores only hashes — never raw text (ADR-9).
type DocumentIndex struct {
	shingles      map[uint64][]uint32 // shingle fingerprint -> doc ids
	docShingles   map[uint32]int      // doc id -> distinct shingle count
	k             int
	matchFraction float64
}

// shingle returns the fingerprints of a text's overlapping word k-grams: lowercase,
// split on runs of non-alphanumeric, join k consecutive words. Normalizing this way
// makes matching robust to whitespace/punctuation/casing and to excerpting.
func shingle(text string, k int) []uint64 {
	if k < 1 {
		k = DefaultShingleK
	}
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	if len(words) < k {
		return nil
	}
	out := make([]uint64, 0, len(words)-k+1)
	for i := 0; i+k <= len(words); i++ {
		s := strings.Join(words[i:i+k], " ")
		sum := sha256.Sum256([]byte(s))
		out = append(out, binary.BigEndian.Uint64(sum[0:8]))
	}
	return out
}

// BuildDocumentIndex fingerprints each document's shingles and returns the index
// plus the number of documents SKIPPED for having fewer than 2 distinct shingles
// (too small to fingerprint meaningfully) — counted, never silently dropped.
func BuildDocumentIndex(docs []string, k int, fraction float64) (*DocumentIndex, int) {
	if k < 1 {
		k = DefaultShingleK
	}
	if fraction <= 0 || fraction > 1 {
		fraction = 0.3
	}
	idx := &DocumentIndex{shingles: map[uint64][]uint32{}, docShingles: map[uint32]int{}, k: k, matchFraction: fraction}
	skipped := 0
	var nextID uint32
	for _, doc := range docs {
		seen := map[uint64]struct{}{}
		for _, fp := range shingle(doc, k) {
			seen[fp] = struct{}{}
		}
		if len(seen) < 2 {
			skipped++
			continue
		}
		id := nextID
		nextID++
		idx.docShingles[id] = len(seen)
		for fp := range seen {
			idx.shingles[fp] = append(idx.shingles[fp], id)
		}
	}
	return idx, skipped
}

// Size reports the number of documents indexed.
func (d *DocumentIndex) Size() int { return len(d.docShingles) }

// bestMatchFraction returns the highest fraction-of-shingles any single document has
// present in the content, and whether any document reached the threshold.
func (d *DocumentIndex) match(text []byte) (matched bool, best float64) {
	if d == nil || len(d.docShingles) == 0 {
		return false, 0
	}
	perDoc := map[uint32]map[uint64]struct{}{}
	for _, fp := range shingle(string(text), d.k) {
		ids, ok := d.shingles[fp]
		if !ok {
			continue
		}
		for _, id := range ids {
			set := perDoc[id]
			if set == nil {
				set = map[uint64]struct{}{}
				perDoc[id] = set
			}
			set[fp] = struct{}{}
		}
	}
	for id, set := range perDoc {
		total := d.docShingles[id]
		if total == 0 {
			continue
		}
		frac := float64(len(set)) / float64(total)
		need := int(math.Ceil(d.matchFraction * float64(total)))
		if need < 1 {
			need = 1
		}
		if len(set) >= need {
			matched = true
			if frac > best {
				best = frac
			}
		}
	}
	return matched, best
}

// idm is the IDM detector.
type idm struct{ index *DocumentIndex }

func (idm) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_IDM }

// Scan reports 1 if any fingerprinted document is substantially present, with a
// confidence scaled by the best matched fraction (capped < 1.0).
func (d idm) Scan(text []byte) (int, float64) {
	matched, best := d.index.match(text)
	if !matched {
		return 0, 0
	}
	conf := 0.7 + 0.29*best
	if conf > 0.99 {
		conf = 0.99
	}
	return 1, conf
}

// AddIDM adds a document-match detector over the given index (DLP-3). A nil/empty
// index is a no-op.
func (c *Classifier) AddIDM(index *DocumentIndex) {
	if index != nil && index.Size() > 0 {
		c.detectors = append(c.detectors, idm{index: index})
	}
}

// NewWithIDM returns the default classifier plus an IDM detector.
func NewWithIDM(index *DocumentIndex) *Classifier {
	c := New()
	c.AddIDM(index)
	return c
}

// Marshal serializes the document index (fingerprints, doc ids, counts, k, fraction)
// — never any raw text.
func (d *DocumentIndex) Marshal() []byte {
	fps := make([]uint64, 0, len(d.shingles))
	for fp := range d.shingles {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool { return fps[i] < fps[j] })

	out := make([]byte, 0, 24+len(fps)*12)
	var hdr [24]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(d.k))
	binary.BigEndian.PutUint64(hdr[4:12], math.Float64bits(d.matchFraction))
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(d.docShingles)))
	binary.BigEndian.PutUint32(hdr[16:20], uint32(len(fps)))
	out = append(out, hdr[:20]...)

	dids := make([]uint32, 0, len(d.docShingles))
	for id := range d.docShingles {
		dids = append(dids, id)
	}
	sort.Slice(dids, func(i, j int) bool { return dids[i] < dids[j] })
	for _, id := range dids {
		var b [8]byte
		binary.BigEndian.PutUint32(b[0:4], id)
		binary.BigEndian.PutUint32(b[4:8], uint32(d.docShingles[id]))
		out = append(out, b[:]...)
	}
	for _, fp := range fps {
		ids := d.shingles[fp]
		var b [12]byte
		binary.BigEndian.PutUint64(b[0:8], fp)
		binary.BigEndian.PutUint32(b[8:12], uint32(len(ids)))
		out = append(out, b[:]...)
		for _, id := range ids {
			var ib [4]byte
			binary.BigEndian.PutUint32(ib[:], id)
			out = append(out, ib[:]...)
		}
	}
	return out
}

// LoadDocumentIndex reconstructs a document index from Marshal bytes.
func LoadDocumentIndex(b []byte) (*DocumentIndex, error) {
	if len(b) < 20 {
		return nil, fmt.Errorf("classify: document index too short")
	}
	k := int(binary.BigEndian.Uint32(b[0:4]))
	frac := math.Float64frombits(binary.BigEndian.Uint64(b[4:12]))
	nDocs := int(binary.BigEndian.Uint32(b[12:16]))
	nFP := int(binary.BigEndian.Uint32(b[16:20]))
	if k < 1 || frac <= 0 || frac > 1 {
		return nil, fmt.Errorf("classify: document index has bad k or fraction")
	}
	off := 20
	idx := &DocumentIndex{shingles: map[uint64][]uint32{}, docShingles: map[uint32]int{}, k: k, matchFraction: frac}
	for i := 0; i < nDocs; i++ {
		if off+8 > len(b) {
			return nil, fmt.Errorf("classify: document index truncated (docs)")
		}
		idx.docShingles[binary.BigEndian.Uint32(b[off:off+4])] = int(binary.BigEndian.Uint32(b[off+4 : off+8]))
		off += 8
	}
	for i := 0; i < nFP; i++ {
		if off+12 > len(b) {
			return nil, fmt.Errorf("classify: document index truncated (shingles)")
		}
		fp := binary.BigEndian.Uint64(b[off : off+8])
		m := int(binary.BigEndian.Uint32(b[off+8 : off+12]))
		off += 12
		ids := make([]uint32, m)
		for j := 0; j < m; j++ {
			if off+4 > len(b) {
				return nil, fmt.Errorf("classify: document index truncated (ids)")
			}
			ids[j] = binary.BigEndian.Uint32(b[off : off+4])
			off += 4
		}
		idx.shingles[fp] = ids
	}
	return idx, nil
}
