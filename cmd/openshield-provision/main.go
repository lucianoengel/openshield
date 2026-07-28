// Command openshield-provision issues the credentials the security stack needs:
// a local CA, role-tagged agent/operator certificates (D58), and escrow keypairs
// (D59). It is an ADMIN AUTHORITY tool, deliberately separate from the read-only
// openshieldctl (which holds no signer) — minting credentials is an authority
// operation, like the server's issue-token.
//
// It is MINIMAL provisioning for dev and small fleets, NOT a full PKI: no
// revocation, no rotation automation, no HSM. The CA private key and the escrow
// private key are the trust roots — guard them (D16).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucianoengel/openshield/internal/provision"
)

const usage = `openshield-provision — issue OpenShield credentials (minimal, not a full PKI)

usage:
  openshield-provision ca-init --out DIR
      write ca.pem + ca-key.pem (the CA private key is the trust root — guard it)

  openshield-provision cert --ca DIR --role agent|operator|analyst|responder|admin \
      --cn NAME [--san S ...] --out DIR
      issue a leaf cert (cert.pem + key.pem) signed by the CA, role in Subject OU

  openshield-provision cert --ca DIR --role client --cn IDENTITY --group GROUP --out DIR
      issue a ZERO-TRUST CLIENT certificate (D86) for the access proxy. The group
      is the authorization group an access policy matches on, and is required —
      a client certificate with no group is one every policy must special-case.

  openshield-provision escrow-keygen --out DIR
      write escrow-pub (to endpoints) + escrow-priv (to the off-endpoint vault)

  openshield-provision witness-keygen --out DIR
      write witness-pub (to verifiers) + witness-priv (to the external witness host)

  openshield-provision risk-keygen --out DIR
      write risk-pub (to gateways) + risk-priv (to the control-plane server) — SEC-1

  openshield-provision posture-enroll --agent AGENT_ID --roster FILE --out DIR
      generate ONE AGENT's posture signing key and add it to the gateway's roster
      (OPENSHIELD_POSTURE_ROSTER). Per-agent keys are what stop one endpoint
      forging another's posture (SEC-12). Appends; re-enrolling replaces.

  openshield-provision intercept-ca --out DIR
      mint the TLS INTERCEPTION CA (OPENSHIELD_INTERCEPT_CA_CERT/KEY). SEPARATE
      from the fleet CA on purpose: whoever holds this can impersonate any host
      to every endpoint trusting it. Deploy the cert only where interception is
      authorised, and guard the key like the fleet CA's.

  openshield-provision attest-capture --subject PSEUDONYM --pcrs 0,7 [--tpm ADDR] --out FILE
      read the LOCAL TPM's AK public key + PCR baseline into the gateway's
      enrollments file (OPENSHIELD_ATTEST_ENROLLMENTS). The offline alternative to
      network self-enrollment, for operators who want no device self-assertion.
      Merges — capturing one device never unenrolls the others.

  openshield-provision usb-authorize [--block] [--sysfs DIR]
      clear the USB posture latch a BLOCK decision set — newly attached devices are
      permitted again. --block re-applies it by hand. Needs root; the enforcer never
      clears it itself, because a machine-wide switch must not be released by the
      next permitted keyboard.

  openshield-provision recover --in BLOB --out FILE --key KEYFILE
  openshield-provision recover --in BLOB --out FILE --escrow-pub PUB --escrow-priv PRIV
      reverse ENCRYPT_LOCAL. The blob's header selects the key; recovery never
      overwrites, because the ciphertext may be the only copy of the data.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "ca-init":
		return caInit(flags(args[1:]))
	case "cert":
		return cert(flags(args[1:]))
	case "escrow-keygen":
		return escrowKeygen(flags(args[1:]))
	case "witness-keygen":
		return witnessKeygen(flags(args[1:]))
	case "risk-keygen":
		return riskKeygen(flags(args[1:]))
	case "posture-keygen":
		return postureKeygen(flags(args[1:]))
	case "recover":
		return recoverFile(flags(args[1:]))
	case "usb-authorize":
		return usbAuthorize(flags(args[1:]))
	case "attest-capture":
		return attestCapture(flags(args[1:]))
	case "posture-enroll":
		return postureEnroll(flags(args[1:]))
	case "intercept-ca":
		return interceptCA(flags(args[1:]))
	default:
		fmt.Fprintf(os.Stderr, "openshield-provision: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func caInit(f map[string][]string) int {
	out := one(f, "out")
	if out == "" {
		return fail("ca-init requires --out DIR")
	}
	caCert, caKey, err := provision.InitCA()
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "ca.pem"), caCert, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "ca-key.pem"), caKey, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/ca.pem and %s/ca-key.pem (guard ca-key.pem — it can mint any cert)\n", out, out)
	return 0
}

func cert(f map[string][]string) int {
	ca, role, cn, out := one(f, "ca"), one(f, "role"), one(f, "cn"), one(f, "out")
	if ca == "" || role == "" || cn == "" || out == "" {
		return fail("cert requires --ca DIR --role R --cn NAME --out DIR")
	}
	caCert, err := os.ReadFile(filepath.Join(ca, "ca.pem"))
	if err != nil {
		return fail("reading CA cert: %v", err)
	}
	caKey, err := os.ReadFile(filepath.Join(ca, "ca-key.pem"))
	if err != nil {
		return fail("reading CA key: %v", err)
	}
	// ZERO-TRUST CLIENT certificates have their OWN issuance path, and until D305 nothing could reach
	// it (`IssueClientCert` had no caller). That was not merely dead code: the access proxy REQUIRES a
	// certificate with the client role AND an authorization group, and refuses an agent or operator
	// certificate by design (D86). So the entire access mode was unusable — a deployment could configure
	// it, the binary would start and log "ZERO-TRUST ACCESS MODE", and no certificate the product could
	// issue would ever be admitted.
	//
	// The GROUP is what a policy authorizes on, so it is required rather than defaulted: a client
	// certificate with no group is one every policy has to special-case.
	var certPEM, keyPEM []byte
	if role == provision.RoleClient {
		group := one(f, "group")
		if group == "" {
			return fail("a client certificate needs --group (the authorization group a policy matches on)")
		}
		certPEM, keyPEM, err = provision.IssueClientCert(caCert, caKey, cn, group)
	} else {
		certPEM, keyPEM, err = provision.IssueCert(caCert, caKey, cn, role, f["san"])
	}
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "cert.pem"), certPEM, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "key.pem"), keyPEM, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/cert.pem and %s/key.pem (role=%s, cn=%s)\n", out, out, role, cn)
	return 0
}

func escrowKeygen(f map[string][]string) int {
	out := one(f, "out")
	if out == "" {
		return fail("escrow-keygen requires --out DIR")
	}
	pub, priv, err := provision.EscrowKeypair()
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "escrow-pub"), pub, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "escrow-priv"), priv, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/escrow-pub (to endpoints) and %s/escrow-priv (to the off-endpoint vault)\n", out, out)
	return 0
}

func witnessKeygen(f map[string][]string) int {
	out := one(f, "out")
	if out == "" {
		return fail("witness-keygen requires --out DIR")
	}
	pub, priv, err := provision.WitnessKeypair()
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "witness-pub"), pub, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "witness-priv"), priv, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/witness-pub (to verifiers) and %s/witness-priv (to the EXTERNAL witness host — T-019)\n", out, out)
	return 0
}

// riskKeygen generates the control-plane risk-signing keypair (SEC-1): risk-priv goes to
// the server (OPENSHIELD_RISK_SIGNING_KEY), risk-pub to every gateway
// (OPENSHIELD_RISK_PUBKEY) so it can verify published risk came from the control plane.
func riskKeygen(f map[string][]string) int {
	out := one(f, "out")
	if out == "" {
		return fail("risk-keygen requires --out DIR")
	}
	pub, priv, err := provision.WitnessKeypair() // a raw ed25519 keypair — same shape
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "risk-pub"), pub, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "risk-priv"), priv, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/risk-pub (to gateways, OPENSHIELD_RISK_PUBKEY) and %s/risk-priv (to the server, OPENSHIELD_RISK_SIGNING_KEY — SEC-1)\n", out, out)
	return 0
}

// postureKeygen generates the device-posture signing keypair (HON-4/SEC-1): posture-priv to
// the reporting agents (OPENSHIELD_POSTURE_SIGNING_KEY), posture-pub to every gateway
// (OPENSHIELD_POSTURE_PUBKEY) so it can verify published posture.
// postureKeygen is the SUPERSEDED shared-key form, kept so an existing deployment's scripts do not break
// — but it now says so (D315). It produced one keypair for a whole fleet, which SEC-12 replaced precisely
// because any holder could forge any other agent's posture, and it told operators to install the public
// half as OPENSHIELD_POSTURE_PUBKEY, which the gateway no longer reads. Following it produced a
// deployment whose posture channel was inert.
func postureKeygen(f map[string][]string) int {
	fmt.Fprintln(os.Stderr, "openshield-provision: WARNING — posture-keygen makes ONE key for the whole "+
		"fleet, which lets any agent holding it forge any other agent's posture. The gateway verifies "+
		"against a per-agent ROSTER (SEC-12) — there is no gateway setting for a shared public key, and "+
		"the one this command used to name has been removed (D333). Use "+
		"`posture-enroll --agent ... --roster ...` instead.")
	out := one(f, "out")
	if out == "" {
		return fail("posture-keygen requires --out DIR")
	}
	pub, priv, err := provision.WitnessKeypair()
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "posture-pub"), pub, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "posture-priv"), priv, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/posture-pub and %s/posture-priv\n", out, out)
	return 0
}

// interceptCA mints the TLS interception CA (D315).
//
// `provision.InterceptionCA` was written with a long comment explaining why it must be SEPARATE from the
// fleet CA — an interception CA can sign a trusted certificate for any host, so its holder can impersonate
// the whole internet to every endpoint that trusts it — and it had no caller. The gateway read
// OPENSHIELD_INTERCEPT_CA_CERT/KEY and nothing could produce them, so the only way to enable HTTPS
// inspection was to mint a CA with openssl by hand, at which point the separation the comment argues for
// is whatever the operator happened to do.
func interceptCA(f map[string][]string) int {
	out := one(f, "out")
	if out == "" {
		return fail("intercept-ca requires --out DIR")
	}
	cert, key, err := provision.InterceptionCA()
	if err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "intercept-ca.pem"), cert, 0o644); err != nil {
		return fail("%v", err)
	}
	if err := writeFile(filepath.Join(out, "intercept-ca-key.pem"), key, 0o600); err != nil {
		return fail("%v", err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s/intercept-ca.pem and %s/intercept-ca-key.pem\n", out, out)
	// Said plainly because the consequence is not obvious from the file names, and because an operator
	// deciding where to install this is making a bigger decision than "turn on HTTPS inspection".
	fmt.Fprintln(os.Stderr, "openshield-provision: installing intercept-ca.pem as a trusted root lets "+
		"the holder of intercept-ca-key.pem impersonate ANY HOST to that machine — banks, the update "+
		"server, everything. It is a far larger authority than the fleet CA, which only authorises "+
		"agents and operators. Install it ONLY where interception is authorised, and give it the same "+
		"custody as the fleet CA key or better.")
	fmt.Fprintln(os.Stderr, "openshield-provision: OPENSHIELD_NO_INTERCEPT exists for the hosts that "+
		"must NOT be intercepted — certificate-pinned apps that will break, and traffic an employer has "+
		"no business reading (banking, health). Set it before turning interception on, not after.")
	return 0
}

// flags parses a tiny `--key value` set; a flag may repeat (e.g. --san). Booleans
// are not needed here.
func flags(args []string) map[string][]string {
	m := map[string][]string{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			continue
		}
		key := strings.TrimPrefix(args[i], "--")
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			m[key] = append(m[key], args[i+1])
			i++
		} else {
			m[key] = append(m[key], "")
		}
	}
	return m
}

func one(f map[string][]string, k string) string {
	if v := f[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}

func fail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "openshield-provision: "+format+"\n", a...)
	return 1
}

// has reports whether a boolean flag was given. Presence IS the value: `--block` means block, and
// `--block=false` is not a form this parser accepts, so a flag that appears is never read as off.
func has(f map[string][]string, k string) bool {
	_, ok := f[k]
	return ok
}
