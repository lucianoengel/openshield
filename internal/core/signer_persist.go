package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"os"
)

// SignerState is the serialisable form of a Signer's CURRENT state (T-009 seam).
//
// It carries the CURRENT epoch's private key ONLY — never a destroyed one. That
// keeps forward security intact: the current epoch is already the compromise
// window (its key must exist to sign), and every earlier private key was
// destroyed on evolution and is absent here. Reloading restores exactly the
// writing capability the running agent already had, and no more.
type SignerState struct {
	Epoch uint64
	Priv  []byte     // current epoch private key
	Chain []KeyEpoch // public material
}

// Export serialises the signer's current state so a restarted process can resume
// the SAME chain. gob is used only for our own trusted export, not attacker
// input, so its caveats do not apply; LoadSigner still validates shape.
func (s *Signer) Export() ([]byte, error) {
	st := SignerState{
		Epoch: s.epoch,
		Priv:  append([]byte(nil), s.priv...),
		Chain: s.Chain(),
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(st); err != nil {
		return nil, fmt.Errorf("signer: export: %w", err)
	}
	// Prefix a SHA-256 of the payload so ANY corruption of the file fails to
	// load. This is an integrity check against accidental corruption, not a MAC:
	// an attacker who can rewrite this file has host access and has already won
	// (D16); the checksum's job is to reject a truncated or bit-rotted blob, not
	// a forged one.
	payload := buf.Bytes()
	sum := sha256.Sum256(payload)
	return append(sum[:], payload...), nil
}

// LoadSigner reconstructs a Signer from an Export blob, validating that the
// private key actually matches the chain's current epoch — a corrupted or
// mismatched blob fails to load rather than producing a signer that signs under a
// key the chain does not list.
func LoadSigner(blob []byte) (*Signer, error) {
	if len(blob) < sha256.Size {
		return nil, fmt.Errorf("signer: load: blob too short")
	}
	sum, payload := blob[:sha256.Size], blob[sha256.Size:]
	want := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(sum, want[:]) != 1 {
		return nil, fmt.Errorf("signer: load: integrity check failed (corrupt or truncated blob)")
	}

	var st SignerState
	if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(&st); err != nil {
		return nil, fmt.Errorf("signer: load: %w", err)
	}
	if len(st.Chain) == 0 {
		return nil, fmt.Errorf("signer: load: empty chain")
	}
	// The whole public chain must be internally consistent (each epoch's key
	// signed by its predecessor), so corruption anywhere in the chain — not just
	// at the current epoch — is caught.
	if _, err := VerifyKeyChain(st.Chain, st.Chain[0].PublicKey); err != nil {
		return nil, fmt.Errorf("signer: load: %w", err)
	}
	if len(st.Priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: load: private key wrong size (%d)", len(st.Priv))
	}
	if st.Epoch >= uint64(len(st.Chain)) {
		return nil, fmt.Errorf("signer: load: epoch %d beyond chain length %d", st.Epoch, len(st.Chain))
	}
	priv := ed25519.PrivateKey(st.Priv)
	wantPub := priv.Public().(ed25519.PublicKey)
	if !wantPub.Equal(st.Chain[st.Epoch].PublicKey) {
		return nil, fmt.Errorf("signer: load: private key does not match chain epoch %d — "+
			"a signer must never sign under a key the chain omits", st.Epoch)
	}
	return &Signer{epoch: st.Epoch, priv: priv, chain: st.Chain}, nil
}

// SaveSignerFile writes the signer's current state to path atomically at mode
// 0600. At-rest protection is filesystem permissions + the agent user; host root
// defeats it (D16), the same bar as reading process memory. Encryption at rest is
// a noted hardening follow-up.
func SaveSignerFile(path string, s *Signer) error {
	blob, err := s.Export()
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("signer: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("signer: committing %s: %w", path, err)
	}
	return nil
}

// LoadSignerFile reads a signer saved by SaveSignerFile.
func LoadSignerFile(path string) (*Signer, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signer: reading %s: %w", path, err)
	}
	return LoadSigner(blob)
}
