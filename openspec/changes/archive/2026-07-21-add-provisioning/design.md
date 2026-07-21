## Context

The consumers already exist and fix the formats: `tlsconf.Load(caPath, certPath,
keyPath)` reads PEM (a CA bundle + a cert/key pair); the role gate (D58) reads the
role from the client cert's Subject OU (`agent`/`operator`); `encryptlocal.NewEscrow`
reads a 32-byte raw public key, and `DecryptEscrow` takes the raw public+private
keys. Provisioning must emit exactly those formats so the loop closes without
changing any consumer.

## Goals / Non-Goals

**Goals:**
- Issue a CA, role-tagged leaf certs, and escrow keypairs that the EXISTING
  consumers accept unchanged.
- Prove the loop: issued certs verify against the CA, carry the right OU, handshake
  under mutual TLS, and drive the real role gate (operator → /view, agent → 403);
  escrow keypairs round-trip.
- Keep the authority (signer) out of the read-only `openshieldctl`.

**Non-Goals:**
- A real PKI: no revocation/CRL/OCSP, no rotation, no intermediate CAs, no HSM.
- Key custody / distribution / a vault — the tool WRITES the private keys to
  files; where they then live is the operator's problem (documented, D16).
- Changing any consumer (tlsconf, role gate, escrow).

## Decisions

**Logic in `internal/provision`, CLI is a thin shell.** `InitCA() (caCertPEM,
caKeyPEM []byte, err error)`, `IssueCert(caCertPEM, caKeyPEM []byte, cn, role
string, sans []string) (certPEM, keyPEM []byte, err error)`, `EscrowKeypair()
(pub, priv []byte, err error)`. The package returns bytes; the command writes
files with restrictive modes (keys 0600). This keeps the whole thing testable
without spawning a process or touching disk.

**Ed25519 throughout for certs.** The CA and leaves are Ed25519 — small, fast, and
already what the tests and `tlsconf` handle. Leaves get `serverAuth` + `clientAuth`
EKU (a cert may be presented as either end), the role in a single OU, and the
caller-supplied SANs (a server cert needs them; a pure client cert does not).

**Role validation against the D58 constants.** `IssueCert` rejects any role that
is not `agent` or `operator`. To prevent drift from D58, a test asserts the
provision role strings equal `controlplane.RoleAgent`/`RoleOperator` — if D58
renames a role and provisioning is not updated, the test fails.

**Escrow keys are raw 32-byte files.** `NewEscrow` reads a raw 32-byte public key,
so the tool writes raw bytes (not PEM) for the escrow pair — matching the consumer
exactly. The public key file is safe to distribute to endpoints; the private key
file is the vault secret.

**The command is separate from openshieldctl.** `openshieldctl` is a read surface
that "holds no signer and can produce no entry." A CA private key is a signer;
putting it behind the same binary would break that asymmetry. `openshield-provision`
is the authority tool, mirroring how `openshield-server issue-token` is an
admin-local operation, not a network route.

## Risks / Trade-offs

- **The CA key is the whole trust root (D16).** Whoever holds `ca-key.pem` can mint
  any cert — an operator cert included, which under D58 grants `/view`. The tool
  cannot mitigate this; it writes the key 0600 and documents that its custody is
  the security boundary. A real deployment fronts issuance with a proper CA/vault.
- **No revocation.** A leaked leaf cert is valid until it expires; there is no CRL.
  Certs get a bounded lifetime (a default validity), and rotation is manual
  (re-issue). Documented as the minimal-PKI limit.
- **Raw escrow key files are easy to mishandle.** A private escrow key written to
  disk is only as safe as that disk (D16). The tool names the files clearly
  (`escrow-pub`/`escrow-priv`) and documents that the private key belongs off the
  endpoint; it does not enforce where it goes.
- **This adds an authority binary.** More surface, but it holds no network
  listener and no persistent state — it reads inputs, writes files, exits. The
  blast radius is the files it writes, which the operator already controls.
