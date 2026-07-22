// Package attest implements the hardware root-of-trust primitive OpenShield
// posture attestation is built on: creating a TPM Attestation Key (AK),
// producing a nonce-bound TPM quote over a set of PCRs, and verifying that
// quote server-side against the AK public key.
//
// It is built directly on github.com/google/go-tpm (a low-level, dependency-
// light TPM 2.0 library already in the module graph) rather than
// github.com/google/go-tpm-tools, whose current releases pull a large
// confidential-computing dependency tree (Intel TDX, AMD SEV-SNP, GCP
// confidential-space) that is irrelevant to a TPM quote. See docs/decisions.md.
//
// This is ZT-1 increment 1 of 4: the quote generate/verify core. Binding the
// AK to a genuine TPM via its Endorsement Key certificate (increment 2),
// measured-boot event-log parsing and PCR policy (increment 3), and wiring an
// `attested` posture signal (increment 4) are separate increments. In
// particular, until EK binding lands, a verifier trusts an AK by its raw public
// key only — it cannot yet distinguish a genuine-TPM AK from one an attacker
// generated on a compromised host.
package attest

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// EnvTPMAddr, when set to a host:port, points the agent at a TCP-connected TPM
// (a swtpm socket in dev and tests) instead of the platform TPM device.
const EnvTPMAddr = "OPENSHIELD_TPM_ADDR"

// TPM is an open connection to a TPM 2.0 device.
type TPM struct {
	tpm    transport.TPM
	closer io.Closer
}

// Open connects to a TPM. If addr (or the OPENSHIELD_TPM_ADDR environment
// variable) is a host:port, it dials that TCP socket — the swtpm software TPM
// used in dev and tests. Otherwise it opens the platform TPM device. The caller
// must Close the returned TPM.
//
// Open does not run TPM2_Startup: a platform TPM is already started by firmware.
// Tests drive a freshly-spawned swtpm and call Startup themselves.
func Open(addr string) (*TPM, error) {
	if addr == "" {
		addr = os.Getenv(EnvTPMAddr)
	}
	if addr != "" {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("attest: dial swtpm %q: %w", addr, err)
		}
		return &TPM{tpm: transport.FromReadWriter(conn), closer: conn}, nil
	}
	dev, err := openDevice()
	if err != nil {
		return nil, err
	}
	return &TPM{tpm: dev, closer: dev}, nil
}

// Startup issues TPM2_Startup(CLEAR). It is only needed for a software TPM that
// has not been initialised; a platform TPM rejects it as already-started.
func (t *TPM) Startup() error {
	_, err := tpm2.Startup{StartupType: tpm2.TPMSUClear}.Execute(t.tpm)
	if err != nil {
		return fmt.Errorf("attest: TPM2_Startup: %w", err)
	}
	return nil
}

// Close releases the underlying transport.
func (t *TPM) Close() error {
	if t.closer == nil {
		return nil
	}
	return t.closer.Close()
}
