//go:build !linux

package attest

import (
	"errors"

	"github.com/google/go-tpm/tpm2/transport"
)

// openDevice has no platform TPM device outside Linux in this increment. The
// TCP path (OPENSHIELD_TPM_ADDR / swtpm) still works everywhere, and quote
// verification is pure Go and platform-independent.
func openDevice() (transport.TPMCloser, error) {
	return nil, errors.New("attest: no TPM device on this platform; set " + EnvTPMAddr)
}
