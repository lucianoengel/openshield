//go:build linux

package attest

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// DefaultDevice is the Linux TPM resource-manager device. The resource manager
// (rm) variant lets an unprivileged process share the TPM without managing
// transient object slots by hand.
const DefaultDevice = "/dev/tpmrm0"

func openDevice() (transport.TPMCloser, error) {
	dev, err := linuxtpm.Open(DefaultDevice)
	if err != nil {
		return nil, fmt.Errorf("attest: open %s: %w", DefaultDevice, err)
	}
	return dev, nil
}
