package classify

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// RecordIndex is a record-structured EDM index (DLP-3, multi-cell): it maps each
// distinctive cell's fingerprint to the records that contain it, so the scanner can
// require a THRESHOLD of distinct cells of the SAME record to co-occur before firing.
// Coincidentally matching several specific fields of one record is astronomically
// unlikely, so this is far lower false-positive than single-value EDM. It stores
// only hashes and integer ids — never raw values in cleartext (ADR-9). As with EDMIndex,
// the hashes are UNSALTED: this stops bulk cleartext exfiltration of the dataset, but a
// low-entropy cell value remains confirmable by an offline guess-and-hash membership probe
// (R34-13) — documented honestly, not called "anonymized".
type RecordIndex struct {
	cells       map[uint64][]uint32 // cell fingerprint -> record ids containing it
	recordCells map[uint32]int      // record id -> its distinct-cell count
	threshold   int                 // distinct same-record cells required to match
}

// cellFingerprint is the first 8 bytes of SHA-256 over the normalized cell. A
// 64-bit truncation collides at ~D²/2⁶⁴ (negligible for realistic dataset sizes),
// and the ≥threshold-distinct-cells requirement compounds independent collisions to
// astronomically unlikely.
func cellFingerprint(value string) uint64 {
	sum := sha256.Sum256([]byte(normalizeEDM(value)))
	return binary.BigEndian.Uint64(sum[0:8])
}

// BuildRecordIndex fingerprints each record's distinctive cells and returns the
// index plus the number of records SKIPPED for having fewer than threshold
// distinctive cells (they could never match — never a silent drop). threshold < 2
// is clamped to 2 (multi-cell means at least two).
func BuildRecordIndex(records [][]string, threshold int) (*RecordIndex, int) {
	if threshold < 2 {
		threshold = 2
	}
	idx := &RecordIndex{cells: map[uint64][]uint32{}, recordCells: map[uint32]int{}, threshold: threshold}
	skipped := 0
	var nextID uint32
	for _, rec := range records {
		// Distinctive cell fingerprints for this record (de-duplicated).
		seen := map[uint64]struct{}{}
		for _, cell := range rec {
			if !distinctiveEDM(cell) {
				continue
			}
			seen[cellFingerprint(cell)] = struct{}{}
		}
		if len(seen) < threshold {
			skipped++
			continue
		}
		id := nextID
		nextID++
		idx.recordCells[id] = len(seen)
		for fp := range seen {
			idx.cells[fp] = append(idx.cells[fp], id)
		}
	}
	return idx, skipped
}

// Size reports the number of records indexed.
func (r *RecordIndex) Size() int { return len(r.recordCells) }

// matchRecords returns how many records reach the threshold of distinct cells in
// the given content.
func (r *RecordIndex) matchRecords(text []byte) int {
	if r == nil || len(r.recordCells) == 0 {
		return 0
	}
	// Per record, the SET of distinct cell fingerprints of THAT record seen in the
	// content — so two hits on the same cell do not double-count, and cells from
	// different records never combine.
	perRecord := map[uint32]map[uint64]struct{}{}
	toks := strings.FieldsFunc(string(text), func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsDigit(c)
	})
	norm := make([]string, len(toks))
	for i, t := range toks {
		norm[i] = normalizeEDM(t)
	}
	for i := range norm {
		var w strings.Builder
		for span := 0; span < MaxEDMSpan && i+span < len(norm); span++ {
			w.WriteString(norm[i+span])
			if w.Len() < MinEDMTokenLen {
				continue
			}
			fp := fingerprintNormalized(w.String())
			ids, ok := r.cells[fp]
			if !ok {
				continue
			}
			for _, id := range ids {
				set := perRecord[id]
				if set == nil {
					set = map[uint64]struct{}{}
					perRecord[id] = set
				}
				set[fp] = struct{}{}
			}
		}
	}
	matches := 0
	for id, set := range perRecord {
		if len(set) >= min(r.threshold, r.recordCells[id]) {
			matches++
		}
	}
	return matches
}

// fingerprintNormalized fingerprints an ALREADY-normalized string (the scan builds
// normalized windows directly), avoiding a redundant normalize.
func fingerprintNormalized(norm string) uint64 {
	sum := sha256.Sum256([]byte(norm))
	return binary.BigEndian.Uint64(sum[0:8])
}

// edmRecord is the record-level EDM detector.
type edmRecord struct{ index *RecordIndex }

func (edmRecord) Type() corev1.DetectorType { return corev1.DetectorType_DETECTOR_TYPE_EDM }

// Scan reports the number of records whose cells co-occur above the threshold. A
// multi-cell record match is near-definitive, so confidence is high (capped < 1.0).
func (d edmRecord) Scan(text []byte) (int, float64) {
	n := d.index.matchRecords(text)
	if n == 0 {
		return 0, 0
	}
	return n, 0.99
}

// AddRecordEDM adds a record-level EDM detector over the given index. A nil/empty
// index is a no-op.
func (c *Classifier) AddRecordEDM(index *RecordIndex) {
	if index != nil && index.Size() > 0 {
		c.detectors = append(c.detectors, edmRecord{index: index})
	}
}

// NewWithRecordEDM returns the default classifier plus a record-EDM detector.
func NewWithRecordEDM(index *RecordIndex) *Classifier {
	c := New()
	c.AddRecordEDM(index)
	return c
}

// Marshal serializes the record index (fingerprints, record ids, counts, threshold)
// — never any raw value.
func (r *RecordIndex) Marshal() []byte {
	// Deterministic order for a stable, diff-able blob.
	fps := make([]uint64, 0, len(r.cells))
	for fp := range r.cells {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool { return fps[i] < fps[j] })

	out := make([]byte, 0, 16+len(fps)*12)
	var hdr [16]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(r.threshold))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(r.recordCells)))
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(fps)))
	out = append(out, hdr[:12]...)
	// record id -> cell count
	rids := make([]uint32, 0, len(r.recordCells))
	for id := range r.recordCells {
		rids = append(rids, id)
	}
	sort.Slice(rids, func(i, j int) bool { return rids[i] < rids[j] })
	for _, id := range rids {
		var b [8]byte
		binary.BigEndian.PutUint32(b[0:4], id)
		binary.BigEndian.PutUint32(b[4:8], uint32(r.recordCells[id]))
		out = append(out, b[:]...)
	}
	// fingerprint -> record ids
	for _, fp := range fps {
		ids := r.cells[fp]
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

// LoadRecordIndex reconstructs a record index from Marshal bytes.
func LoadRecordIndex(b []byte) (*RecordIndex, error) {
	if len(b) < 12 {
		return nil, fmt.Errorf("classify: record index too short")
	}
	threshold := int(binary.BigEndian.Uint32(b[0:4]))
	nRecords := int(binary.BigEndian.Uint32(b[4:8]))
	nFP := int(binary.BigEndian.Uint32(b[8:12]))
	off := 12
	idx := &RecordIndex{cells: map[uint64][]uint32{}, recordCells: map[uint32]int{}, threshold: threshold}
	for i := 0; i < nRecords; i++ {
		if off+8 > len(b) {
			return nil, fmt.Errorf("classify: record index truncated (records)")
		}
		id := binary.BigEndian.Uint32(b[off : off+4])
		cnt := int(binary.BigEndian.Uint32(b[off+4 : off+8]))
		idx.recordCells[id] = cnt
		off += 8
	}
	for i := 0; i < nFP; i++ {
		if off+12 > len(b) {
			return nil, fmt.Errorf("classify: record index truncated (fingerprints)")
		}
		fp := binary.BigEndian.Uint64(b[off : off+8])
		m := int(binary.BigEndian.Uint32(b[off+8 : off+12]))
		off += 12
		// R34-8: bound the id count by the bytes actually remaining BEFORE allocating,
		// so a malformed blob claiming m=0xFFFFFFFF cannot drive a multi-GB make().
		if m < 0 || m > (len(b)-off)/4 {
			return nil, fmt.Errorf("classify: record index truncated (ids: claims %d, blob has room for %d)", m, (len(b)-off)/4)
		}
		ids := make([]uint32, m)
		for j := 0; j < m; j++ {
			if off+4 > len(b) {
				return nil, fmt.Errorf("classify: record index truncated (ids)")
			}
			ids[j] = binary.BigEndian.Uint32(b[off : off+4])
			off += 4
		}
		idx.cells[fp] = ids
	}
	if threshold < 2 {
		return nil, fmt.Errorf("classify: record index threshold < 2")
	}
	return idx, nil
}
