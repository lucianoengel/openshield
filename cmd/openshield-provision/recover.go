package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/lucianoengel/openshield/internal/enforcers/encryptlocal"
)

// RECOVERY for ENCRYPT_LOCAL (D293).
//
// The enforcer that encrypts a flagged file in place is wired and shipping. Nothing could decrypt one.
// `Decrypt` carried the comment "exported because operator recovery is a real operation" and had no
// caller; `DecryptEscrow`'s doc called it "the recovery operation, run by the off-endpoint private-key
// holder", and there was no such operation to run.
//
// That is not an ordinary unwired feature. The ENCRYPTING half works, so enabling ENCRYPT_LOCAL made a
// user's file permanently unreadable with no shipped way to get it back — a containment action that is
// indistinguishable, to the person whose file it was, from destroying it. A security product that can
// only take an action it cannot undo is one an operator is right to refuse to enable.
//
// TWO SAFETY PROPERTIES, both about not making a bad day worse:
//
//  1. THE CIPHERTEXT IS NEVER DESTROYED. Recovery writes to a NEW path and refuses to overwrite an
//     existing file. In-place recovery would mean a failed or half-written decrypt leaves neither the
//     plaintext nor the blob, and the blob is the only copy of the data.
//  2. THE BLOB SAYS WHICH KEY IT NEEDS. The two formats have distinct magic headers, so supplying the
//     wrong kind of key is a clear refusal naming the right one, rather than a GCM-tag failure that
//     reads identically to "your key is wrong" or "the file is corrupt".

const recoverUsage = `usage:
  openshield-provision recover --in BLOB --out FILE --key KEYFILE
      recover a symmetric (OSENC1) blob with the endpoint's local key

  openshield-provision recover --in BLOB --out FILE --escrow-pub PUB --escrow-priv PRIV
      recover an escrow (OSENCX1) blob with the off-endpoint keypair
`

func recoverFile(f map[string][]string) int {
	in, out := one(f, "in"), one(f, "out")
	if in == "" || out == "" {
		fmt.Fprint(os.Stderr, recoverUsage)
		return 2
	}
	blob, err := os.ReadFile(in)
	if err != nil {
		return fail("reading %s: %v", in, err)
	}
	// Refuse to clobber. Checked BEFORE decrypting so a wrong --out is caught while everything is still
	// recoverable, rather than after the work is done.
	if _, err := os.Stat(out); err == nil {
		return fail("%s already exists — recovery never overwrites, because the encrypted blob may be "+
			"the only copy of this data", out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail("checking %s: %v", out, err)
	}

	plain, err := recoverBlob(f, blob)
	if err != nil {
		return fail("%v", err)
	}
	// 0600: a recovered file holds whatever the original held, which was flagged as sensitive enough to
	// encrypt. Writing it world-readable would undo the containment as part of reversing it.
	if err := writeFile(out, plain, 0o600); err != nil {
		return fail("writing %s: %v", out, err)
	}
	fmt.Fprintf(os.Stderr, "openshield-provision: recovered %d bytes to %s (the encrypted blob at %s is "+
		"untouched)\n", len(plain), out, in)
	return 0
}

// recoverBlob routes by the blob's own header and reports a MISMATCH as a mismatch.
func recoverBlob(f map[string][]string, blob []byte) ([]byte, error) {
	symKey, escPub, escPriv := one(f, "key"), one(f, "escrow-pub"), one(f, "escrow-priv")
	switch {
	case bytes.HasPrefix(blob, []byte("OSENCX1\x00")):
		if escPub == "" || escPriv == "" {
			return nil, fmt.Errorf("this is an ESCROW blob: it needs --escrow-pub and --escrow-priv, " +
				"which are held off the endpoint. The endpoint's own key cannot open it — that is the " +
				"point of escrow mode")
		}
		pub, err := readKey(escPub)
		if err != nil {
			return nil, err
		}
		priv, err := readKey(escPriv)
		if err != nil {
			return nil, err
		}
		return encryptlocal.DecryptEscrow(pub, priv, blob)
	case bytes.HasPrefix(blob, []byte("OSENC1\x00")):
		if symKey == "" {
			return nil, fmt.Errorf("this is a SYMMETRIC blob: it needs --key, the endpoint's local " +
				"encryption key")
		}
		key, err := readKey(symKey)
		if err != nil {
			return nil, err
		}
		return encryptlocal.Decrypt(key, blob)
	default:
		// Said plainly, because the alternative is an operator concluding their key is wrong and going
		// to look for a different one.
		return nil, fmt.Errorf("this file is not OpenShield-encrypted (no OSENC1 or OSENCX1 header) — " +
			"there is nothing here to recover, and no key will change that")
	}
}

func readKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key %s: %w", path, err)
	}
	if len(b) != encryptlocal.KeySize {
		return nil, fmt.Errorf("key %s is %d bytes, want %d — a truncated key fails as a decryption "+
			"error, which reads like the wrong key rather than a broken one", path, len(b), encryptlocal.KeySize)
	}
	return b, nil
}
