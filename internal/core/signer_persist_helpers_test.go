package core_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"testing"

	"github.com/lucianoengel/openshield/internal/core"
)

// decodeState/wrapState mirror Export's on-disk format (sha256(payload)||payload
// where payload = gob(SignerState)) so a test can craft adversarial blobs.
func decodeState(t *testing.T, blob []byte) core.SignerState {
	t.Helper()
	payload := blob[sha256.Size:]
	var st core.SignerState
	if err := gob.NewDecoder(bytes.NewReader(payload)).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func wrapState(t *testing.T, st core.SignerState) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(st); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return append(sum[:], buf.Bytes()...)
}
