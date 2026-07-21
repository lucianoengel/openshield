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

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// KeySize is the AES-256 key length.
const KeySize = 32

// magic marks an OpenShield-encrypted file, so re-encryption is idempotent and
// Decrypt can reject a blob that is not one of ours.
var magic = []byte("OSENC1\x00")

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
	if !isEncrypted(blob) {
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

func isEncrypted(blob []byte) bool { return bytes.HasPrefix(blob, magic) }

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

// Enforcer encrypts flagged files in place under a fixed key.
type Enforcer struct {
	key []byte
}

// New loads a 32-byte key from a file. A wrong-length key is a load error — the
// enforcer never runs with a weak or truncated key.
func New(keyPath string) (*Enforcer, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("encryptlocal: reading key %s: %w", keyPath, err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryptlocal: key %s is %d bytes, want %d", keyPath, len(key), KeySize)
	}
	return &Enforcer{key: key}, nil
}

// WithKey builds an enforcer from a raw key — for tests and callers holding the
// key already.
func WithKey(key []byte) (*Enforcer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("encryptlocal: key must be %d bytes, got %d", KeySize, len(key))
	}
	return &Enforcer{key: append([]byte(nil), key...)}, nil
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
	data, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("encryptlocal: reading %s: %w", target, err)
	}
	if isEncrypted(data) {
		return nil // already contained — idempotent
	}
	blob, err := Encrypt(e.key, data)
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
