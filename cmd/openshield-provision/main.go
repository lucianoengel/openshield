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

  openshield-provision cert --ca DIR --role agent|operator --cn NAME [--san S ...] --out DIR
      issue a leaf cert (cert.pem + key.pem) signed by the CA, role in Subject OU

  openshield-provision escrow-keygen --out DIR
      write escrow-pub (to endpoints) + escrow-priv (to the off-endpoint vault)

  openshield-provision witness-keygen --out DIR
      write witness-pub (to verifiers) + witness-priv (to the external witness host)
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
	certPEM, keyPEM, err := provision.IssueCert(caCert, caKey, cn, role, f["san"])
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
