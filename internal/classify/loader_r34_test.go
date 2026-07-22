package classify

import (
	"encoding/binary"
	"testing"
)

// TestRecordIndexLoaderRejectsHugeAllocation (R34-8): a malformed record-index blob
// claiming a 4-billion id count must be rejected by the length bound, not trigger a
// multi-GB allocation.
func TestRecordIndexLoaderRejectsHugeAllocation(t *testing.T) {
	// header: threshold=2, nRecords=0, nFP=1; then one fingerprint (8B) + m=0xFFFFFFFF.
	b := make([]byte, 0, 24)
	var hdr [12]byte
	binary.BigEndian.PutUint32(hdr[0:4], 2)          // threshold
	binary.BigEndian.PutUint32(hdr[4:8], 0)          // nRecords
	binary.BigEndian.PutUint32(hdr[8:12], 1)         // nFP
	b = append(b, hdr[:]...)
	var fpEntry [12]byte
	binary.BigEndian.PutUint64(fpEntry[0:8], 0xDEAD) // fingerprint
	binary.BigEndian.PutUint32(fpEntry[8:12], 0xFFFFFFFF) // absurd id count
	b = append(b, fpEntry[:]...)

	if _, err := LoadRecordIndex(b); err == nil {
		t.Fatal("a record index claiming 4B ids must be rejected, not allocated (R34-8)")
	}
}

// TestDocumentIndexLoaderRejectsHugeAllocation (R34-8): same for the IDM loader.
func TestDocumentIndexLoaderRejectsHugeAllocation(t *testing.T) {
	// header: k=5, fraction, nDocs=0, nFP=1; then one shingle (8B) + m=0xFFFFFFFF.
	b := make([]byte, 0, 32)
	var hdr [20]byte
	binary.BigEndian.PutUint32(hdr[0:4], 5)              // k
	binary.BigEndian.PutUint64(hdr[4:12], 0x3FD0000000000000) // some fraction bits (~0.25)
	binary.BigEndian.PutUint32(hdr[12:16], 0)            // nDocs
	binary.BigEndian.PutUint32(hdr[16:20], 1)            // nFP
	b = append(b, hdr[:]...)
	var fpEntry [12]byte
	binary.BigEndian.PutUint64(fpEntry[0:8], 0xBEEF)
	binary.BigEndian.PutUint32(fpEntry[8:12], 0xFFFFFFFF)
	b = append(b, fpEntry[:]...)

	if _, err := LoadDocumentIndex(b); err == nil {
		t.Fatal("a document index claiming 4B ids must be rejected, not allocated (R34-8)")
	}
}

// FuzzLoadRecordIndex ensures the loader never panics/OOMs on arbitrary bytes.
func FuzzLoadRecordIndex(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = LoadRecordIndex(b) // must return (error), never panic or OOM
	})
}
