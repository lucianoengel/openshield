package core_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
)

func TestSignerExportLoad(t *testing.T) {
	s, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	// Evolve a couple of times, so the current key is NOT the anchor key.
	if err := s.Evolve(); err != nil {
		t.Fatal(err)
	}
	if err := s.Evolve(); err != nil {
		t.Fatal(err)
	}

	blob, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}
	// Only the current epoch's private key is present (the state carries one
	// Priv, not one per epoch).
	loaded, err := core.LoadSigner(blob)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Epoch() != s.Epoch() {
		t.Errorf("epoch = %d, want %d", loaded.Epoch(), s.Epoch())
	}
	if !loaded.AnchorKey().Equal(s.AnchorKey()) {
		t.Error("reloaded signer has a different anchor")
	}
	// The reloaded signer signs identically — seal an entry with each and compare.
	e1 := &core.Entry{Sequence: 1}
	e2 := &core.Entry{Sequence: 1}
	prev := core.GenesisHash[:]
	s.Seal(e1, prev)
	loaded.Seal(e2, prev)
	if string(e1.Sig) != string(e2.Sig) {
		t.Error("reloaded signer produced a different signature — it is not the same key")
	}

	// A corrupted blob fails to load.
	bad := append([]byte(nil), blob...)
	bad[len(bad)/2] ^= 0xff
	if _, err := core.LoadSigner(bad); err == nil {
		t.Error("a corrupted blob loaded without error")
	}
}

func TestSignerFile(t *testing.T) {
	s, _ := core.NewSigner()
	_ = s.Evolve()
	dir := t.TempDir()
	path := filepath.Join(dir, "signer.state")

	if err := core.SaveSignerFile(path, s); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("signer file mode = %v, want 0600 — it holds a private key", info.Mode().Perm())
	}
	loaded, err := core.LoadSignerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Epoch() != s.Epoch() || !loaded.AnchorKey().Equal(s.AnchorKey()) {
		t.Error("loaded signer file does not match")
	}
}

// A blob whose private key does not match the chain's current epoch must be
// rejected — a signer must never sign under a key the chain omits. This crafts a
// well-formed, correctly-checksummed blob with a mismatched key, so it exercises
// the priv/chain check specifically (not just the corruption checksum).
func TestPrivChainMismatchRejected(t *testing.T) {
	good, _ := core.NewSigner()
	_ = good.Evolve()
	goodBlob, err := good.Export()
	if err != nil {
		t.Fatal(err)
	}
	// Decode the good state, swap in an UNRELATED private key, re-wrap with a
	// valid checksum (mirroring Export's format: sha256(payload) || payload).
	other, _ := core.NewSigner()
	otherBlob, _ := other.Export()

	goodState := decodeState(t, goodBlob)
	otherState := decodeState(t, otherBlob)
	goodState.Priv = otherState.Priv // valid key, but not this chain's

	bad := wrapState(t, goodState)
	if _, err := core.LoadSigner(bad); err == nil {
		t.Fatal("a blob whose private key does not match the chain loaded — the signer would " +
			"sign under a key the chain omits")
	}
}
