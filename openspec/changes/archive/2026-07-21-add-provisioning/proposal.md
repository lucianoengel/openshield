## Why

The mutual-TLS (D55), cert-role authorization (D58) and key-escrow (D59) work all
assume certificates and keys are issued OUT OF BAND — and nothing issues them.
The only place they exist is hand-rolled `openssl` in `deploy/mtls-e2e.sh`. So the
whole access-security stack is un-deployable: an operator has no supported way to
stand up a CA, mint a role-tagged agent or operator cert, or generate an escrow
keypair. This closes that gap with a minimal, honest provisioning tool.

## What Changes

- A reusable `internal/provision` package: `InitCA` (Ed25519 self-signed CA),
  `IssueCert(ca, cn, role, sans)` (leaf signed by the CA, carrying the role in
  Subject OU per D58, serverAuth+clientAuth EKU), and an escrow-keypair helper
  wrapping `encryptlocal.GenerateEscrowKeypair`.
- A SEPARATE admin command `cmd/openshield-provision` with `ca-init`, `cert
  --role agent|operator --cn NAME [--san …]`, and `escrow-keygen`. It is NOT part
  of `openshieldctl`, which is a deliberately read-only surface holding no signer
  — minting credentials is an AUTHORITY operation, kept separate like the server's
  token issuance.
- The escrow public key is written for endpoints (consumed by `NewEscrow`); the
  escrow private key is written for the off-endpoint vault (consumed by
  `DecryptEscrow`).
- `deploy/mtls-e2e.sh` generates its CA and certs with the provisioning tool
  instead of raw `openssl`, so the live container e2e proves the tool produces
  certs that actually work with the server, the role gate, and the TLS NATS
  broker.

## Capabilities

### New Capabilities
- `provisioning`: minimal issuance of the credentials the security stack needs — a
  local CA, role-tagged agent/operator certificates, and escrow keypairs — so
  mTLS, cert-role authorization and key escrow are deployable end to end.

## Impact

- New code: `internal/provision`, `cmd/openshield-provision`; `deploy/mtls-e2e.sh`
  switched to the tool; a drift guard asserting the tool's role strings equal
  `controlplane.RoleAgent`/`RoleOperator`; docs (new D-number).
- SCOPE, stated honestly: this is MINIMAL provisioning for dev and small fleets,
  NOT a full PKI — no revocation/CRL/OCSP, no rotation automation, no HSM. The CA
  private key and the escrow private key are the crown jewels (D16): whoever holds
  `ca-key.pem` can mint any cert, including an operator cert; whoever holds the
  escrow private key can read every escrowed file. Documented, not overclaimed;
  production should use a real PKI / vault. D14 holds (this issues credentials, it
  does not change what the control plane does).
