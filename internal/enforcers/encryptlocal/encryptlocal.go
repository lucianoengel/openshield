// Package encryptlocal is a post-decision file enforcer (Phase 2, D49/D57).
//
// It carries out ENCRYPT_LOCAL by replacing a flagged file's CONTENTS in place
// with an authenticated ciphertext, so the file is genuinely unreadable without
// the key. Like quarantine, this is CONTAINMENT after detection, not PREVENTION:
// the file was already read (that is how it was classified), so encryption
// contains it after the fact — it does not stop the access that triggered it.
//
// Its protection depends entirely on KEY CUSTODY. At-rest, the key is guarded by
// filesystem permissions + the agent user — the SAME bar as the signer key
// (D16): an on-host key readable by the agent user or host root defeats it. The
// honest value is a stolen disk or a DIFFERENT local user, not the agent user.
package encryptlocal

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/nacl/box"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/enforcers/safeio"
)

// KeySize is the AES-256 key length (symmetric mode) and the Curve25519 key
// length (escrow mode) — both 32 bytes.
const KeySize = 32

// magic marks a SYMMETRIC OpenShield-encrypted file (D57); escrowMagic marks a
// PUBLIC-KEY escrow blob (D59). Distinct headers make a blob self-describing:
// re-encryption is idempotent across modes, and recovery routes to the right key.
var (
	magic       = []byte("OSENC1\x00")
	escrowMagic = []byte("OSENCX1\x00")
)

const nonceSize = 12 // AES-GCM standard nonce

// Encrypt returns magic || nonce || AES-256-GCM(plaintext). The nonce is fresh
// per call. A key of the wrong length is an error, never a silent weak cipher.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encryptlocal: nonce: %w", err)
	}
	out := append([]byte(nil), magic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. A wrong key or any tampering fails the GCM tag —
// this is what makes an encrypted file genuinely unreadable, not just renamed.
// Exported because operator recovery is a real operation.
func Decrypt(key, blob []byte) ([]byte, error) {
	if bytes.HasPrefix(blob, escrowMagic) {
		return nil, fmt.Errorf("encryptlocal: this is an escrow blob — use DecryptEscrow")
	}
	if !bytes.HasPrefix(blob, magic) {
		return nil, fmt.Errorf("encryptlocal: not an OpenShield-encrypted blob")
	}
	rest := blob[len(magic):]
	if len(rest) < nonceSize {
		return nil, fmt.Errorf("encryptlocal: blob too short")
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce, ct := rest[:nonceSize], rest[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("encryptlocal: decrypt failed (wrong key or corrupt): %w", err)
	}
	return pt, nil
}

// isEncrypted recognises EITHER mode's magic, so re-encryption is an idempotent
// no-op regardless of which mode wrote the file.
func isEncrypted(blob []byte) bool {
	return bytes.HasPrefix(blob, magic) || bytes.HasPrefix(blob, escrowMagic)
}

// --- Escrow mode (D59): public-key envelope encryption ---
//
// The endpoint holds only the recipient PUBLIC key and seals to it with an
// anonymous sealed-box (an ephemeral keypair per file, its public part embedded).
// The endpoint CANNOT decrypt what it sealed — recovery needs the recipient
// PRIVATE key, held off the endpoint. This closes the D57 custody gap: a
// fully-compromised endpoint yields ciphertext it cannot open.

// GenerateEscrowKeypair returns a Curve25519 (public, private) keypair. The
// operator provisions the PUBLIC key to endpoints and keeps the PRIVATE key in a
// vault off the endpoint.
func GenerateEscrowKeypair() (pub, priv []byte, err error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("encryptlocal: escrow keygen: %w", err)
	}
	return pk[:], sk[:], nil
}

// EncryptEscrow seals plaintext to the recipient public key. Only the matching
// private key can open it — the caller (endpoint) cannot.
func EncryptEscrow(recipientPub, plaintext []byte) ([]byte, error) {
	if len(recipientPub) != KeySize {
		return nil, fmt.Errorf("encryptlocal: escrow public key must be %d bytes, got %d", KeySize, len(recipientPub))
	}
	var pk [32]byte
	copy(pk[:], recipientPub)
	sealed, err := box.SealAnonymous(nil, plaintext, &pk, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("encryptlocal: escrow seal: %w", err)
	}
	out := append([]byte(nil), escrowMagic...)
	return append(out, sealed...), nil
}

// DecryptEscrow recovers an escrow blob with the recipient keypair — the recovery
// operation, run by the off-endpoint private-key holder. A wrong key fails.
func DecryptEscrow(recipientPub, recipientPriv, blob []byte) ([]byte, error) {
	if !bytes.HasPrefix(blob, escrowMagic) {
		return nil, fmt.Errorf("encryptlocal: not an escrow blob")
	}
	if len(recipientPub) != KeySize || len(recipientPriv) != KeySize {
		return nil, fmt.Errorf("encryptlocal: escrow keys must be %d bytes", KeySize)
	}
	var pk, sk [32]byte
	copy(pk[:], recipientPub)
	copy(sk[:], recipientPriv)
	pt, ok := box.OpenAnonymous(nil, blob[len(escrowMagic):], &pk, &sk)
	if !ok {
		return nil, fmt.Errorf("encryptlocal: escrow open failed (wrong key or corrupt)")
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryptlocal: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encryptlocal: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// Enforcer encrypts flagged files in place. In SYMMETRIC mode (D57) it holds the
// AES key and can decrypt; in ESCROW mode (D59) it holds only the recipient
// PUBLIC key and CANNOT decrypt what it seals. Exactly one mode is set.
type Enforcer struct {
	key       []byte // symmetric AES key (symmetric mode)
	escrowPub []byte // recipient public key (escrow mode)
}

// New loads a 32-byte symmetric key from a file. A wrong-length key is a load
// error — the enforcer never runs with a weak or truncated key.
func New(keyPath string) (*Enforcer, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("encryptlocal: reading key %s: %w", keyPath, err)
	}
	return WithKey(key)
}

// WithKey builds a SYMMETRIC enforcer from a raw key.
func WithKey(key []byte) (*Enforcer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryptlocal: key must be %d bytes, got %d", KeySize, len(key))
	}
	return &Enforcer{key: append([]byte(nil), key...)}, nil
}

// NewEscrow loads a 32-byte recipient PUBLIC key from a file and builds an ESCROW
// enforcer: it can seal to that key but cannot decrypt (D59). The private key is
// held off the endpoint.
func NewEscrow(pubKeyPath string) (*Enforcer, error) {
	pub, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("encryptlocal: reading escrow public key %s: %w", pubKeyPath, err)
	}
	return WithEscrowKey(pub)
}

// WithEscrowKey builds an ESCROW enforcer from a raw recipient public key.
func WithEscrowKey(pub []byte) (*Enforcer, error) {
	if len(pub) != KeySize {
		return nil, fmt.Errorf("encryptlocal: escrow public key must be %d bytes, got %d", KeySize, len(pub))
	}
	return &Enforcer{escrowPub: append([]byte(nil), pub...)}, nil
}

func (e *Enforcer) Capabilities() []corev1.Action {
	return []corev1.Action{corev1.Action_ACTION_ENCRYPT_LOCAL}
}

// Enforce without a target cannot act — encryption needs to know which file. It
// errors rather than silently doing nothing (a no-op enforcement is a
// containment that did not happen but looks like it did).
func (e *Enforcer) Enforce(_ context.Context, _ *corev1.Decision) error {
	return fmt.Errorf("encryptlocal: no target file supplied (use EnforceTarget)")
}

// EnforceTarget encrypts the target file in place, atomically. If the file is
// ALREADY encrypted it returns success without re-encrypting (idempotent). The
// original plaintext is replaced by the ciphertext via a temp-then-rename, so a
// crash leaves either the original or the fully-encrypted file — never a partial.
func (e *Enforcer) EnforceTarget(_ context.Context, _ *corev1.Decision, target string) error {
	if target == "" {
		return fmt.Errorf("encryptlocal: empty target")
	}
	// Read WITHOUT following a symlink at the target: an attacker who swapped the
	// flagged path for a symlink between classification and here must not redirect
	// us onto an arbitrary file (D65). A swapped symlink / non-regular target is
	// refused loudly, never silently followed.
	data, err := safeio.ReadRegularNoFollow(target)
	if err != nil {
		return fmt.Errorf("encryptlocal: reading %s: %w", target, err)
	}
	if isEncrypted(data) {
		return nil // already contained — idempotent (either mode)
	}
	var blob []byte
	if e.escrowPub != nil {
		blob, err = EncryptEscrow(e.escrowPub, data) // endpoint cannot decrypt this
	} else {
		blob, err = Encrypt(e.key, data)
	}
	if err != nil {
		return err
	}
	tmp := target + ".osenc.tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("encryptlocal: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("encryptlocal: committing %s: %w", target, err)
	}
	return nil
}

var (
	_ core.Enforcer         = (*Enforcer)(nil)
	_ core.TargetedEnforcer = (*Enforcer)(nil)
)
