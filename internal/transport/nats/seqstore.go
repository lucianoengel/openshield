package nats

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// reserveBlock is how many sequences a persist reserves ahead, so the seq file is
// written ~once per reserveBlock publishes rather than once per message. A crash
// loses at most reserveBlock-1 reserved-but-unused sequences, which appear as a
// GAP (accepted and counted by the control plane, D50) — never a replay.
const reserveBlock = 100

// SeqStore persists a monotonic high-water mark so a restarted publisher never
// reuses a sequence (D66). Reservation-based: Load returns the last persisted
// high-water; Reserve persists a new one atomically.
type SeqStore interface {
	Load() (uint64, error)
	Reserve(highWater uint64) error
}

// FileSeqStore persists the high-water to a file, atomically (temp+rename, 0600),
// the same discipline as the D46 signer state.
type FileSeqStore struct{ path string }

// NewFileSeqStore returns a store backed by path.
func NewFileSeqStore(path string) *FileSeqStore { return &FileSeqStore{path: path} }

// Load reads the persisted high-water. A missing file is a fresh start (0); a
// present-but-corrupt file is a LOUD error — the publisher must refuse to start
// rather than silently reset to 0 and reintroduce the false-replay bug.
func (s *FileSeqStore) Load() (uint64, error) {
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("seqstore: reading %s: %w", s.path, err)
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("seqstore: %s is %d bytes, want 8 (corrupt — refusing to reset)", s.path, len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

// Reserve persists a new high-water mark atomically.
func (s *FileSeqStore) Reserve(hw uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], hw)
	tmp := s.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("seqstore: %w", err)
	}
	if err := os.WriteFile(tmp, b[:], 0o600); err != nil {
		return fmt.Errorf("seqstore: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("seqstore: committing %s: %w", s.path, err)
	}
	return nil
}
