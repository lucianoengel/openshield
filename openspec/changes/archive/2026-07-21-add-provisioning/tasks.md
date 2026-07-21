# Tasks — minimal provisioning tooling

## 1. Provisioning library

- [x] 1.1 `internal/provision`: `InitCA() (caCertPEM, caKeyPEM []byte, err error)` — Ed25519 self-signed CA, bounded validity.
- [x] 1.2 `IssueCert(caCertPEM, caKeyPEM []byte, cn, role string, sans []string) (certPEM, keyPEM []byte, err error)` — Ed25519 leaf signed by the CA, role in Subject OU, serverAuth+clientAuth EKU, SANs (DNS/IP); reject an invalid role.
- [x] 1.3 `EscrowKeypair() (pub, priv []byte, err error)` wrapping `encryptlocal.GenerateEscrowKeypair`.
- [x] 1.4 Role constants (`RoleAgent`/`RoleOperator`) with a drift-guard test asserting they equal `controlplane.RoleAgent`/`RoleOperator`.

## 2. The command

- [x] 2.1 `cmd/openshield-provision`: `ca-init --out DIR`, `cert --ca DIR --role R --cn NAME [--san S…] --out DIR`, `escrow-keygen --out DIR`. Private keys written 0600; usage on bad args.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: an issued leaf VERIFIES against the CA (x509), carries the correct OU role, and loads via `tlsconf.Load` without error; an invalid role is rejected.
- [x] 3.2 **Test (loop-closing)**: a provisioned operator cert authorizes for `/view` and a provisioned agent cert is `403` — driving the REAL role gate with tool-issued certs.
- [x] 3.3 **Test**: a provisioned escrow keypair round-trips — `NewEscrow(pub)` seals, `DecryptEscrow(pub, priv)` recovers the exact original, a wrong private key fails.
- [x] 3.4 **Test**: the role-constant drift guard (provision roles == controlplane roles).

## 4. Wire the live e2e

- [x] 4.1 `deploy/mtls-e2e.sh`: build `openshield-provision` and generate the CA + server/agent(OU=agent)/operator(OU=operator) certs with it instead of raw openssl; the existing assertions (enroll, verified telemetry, role 403s) now prove the TOOL's output works end to end.

## 5. Docs, ship

- [x] 5.1 `docs/decisions.md` new D-number: minimal provisioning makes the mTLS/role/escrow stack deployable; NOT a full PKI (no revocation/rotation/HSM); CA-key and escrow-key custody are the trust roots (D16); separate authority binary, not in read-only openshieldctl.
- [x] 5.2 `openspec validate add-provisioning --strict`; `make all`; archive via the skill; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| IssueCert drops the role OU | `TestIssuedCertVerifiesAndCarriesRole`, `TestProvisionedCertsDriveRoleGate` |
| IssueCert skips role validation | `TestIssuedCertVerifiesAndCarriesRole` (invalid role issued) |
| leaf self-signed, not CA-signed | `TestIssuedCertVerifiesAndCarriesRole` (x509 verify fails) |
| EscrowKeypair returns pub as priv | `TestProvisionedEscrowKeypairRoundTrips` (wrong-key check) |

The provisioning tool issues credentials the EXISTING consumers accept unchanged:
issued leaves verify against the CA (x509), carry the right OU role, and load via
`tlsconf.Load`; a provisioned operator cert authorizes for `/view` and an agent
cert is 403 driving the REAL D58 gate; a provisioned escrow keypair round-trips
through `NewEscrow`/`DecryptEscrow`. A drift guard ties the tool's roles to the
gate's. Proven live in `deploy/mtls-e2e.sh`, which now generates its CA + certs
with the tool instead of raw openssl.
