## Why

The interception CA (D75) is a skeleton key — it can impersonate any site — and the
minimal PKI has no CRL/OCSP/rotation (D60). If it is compromised or nearing
expiry, there is today no way to replace it without a restart, and no stated answer
to "how do you revoke?" This makes the CA hot-rotatable and records honestly what
revocation means here.

## What Changes

- `CertMinter.Rotate(caCertPEM, caKeyPEM)` — validate the new CA FIRST; only if
  valid, under the mutex, atomically swap the CA and FLUSH the leaf cache (cached
  leaves chain to the OLD CA, so a stale leaf must never be served after rotation).
  A bad rotation keeps the old CA and returns an error — fail-safe, never leaves the
  minter broken or interception silently off.
- The leaf validity becomes a named const with the revocation posture documented:
  the SHORT leaf TTL (~24h) is the minimal PKI's answer to leaf revocation — an
  ephemeral per-host leaf self-limits, so no CRL/OCSP is needed; CA-level revocation
  is rotate-away or remove-to-tunnel (drop the CA config → interception off, D74).
- `cmd/openshield-gateway`: on SIGHUP, reload the interception CA files and
  `Rotate` — replace the CA in place without dropping connections; a reload error is
  logged and the old CA keeps serving.

## Capabilities

### Modified Capabilities
- `network-gateway`: the interception CA is hot-rotatable (validate → atomic swap →
  flush cache, fail-safe, SIGHUP reload) — no restart to replace a compromised CA.
- `provisioning`: the interception-CA rotation/revocation posture in the minimal PKI
  is documented (short leaf TTL as leaf revocation; rotate-away/remove-to-tunnel as
  CA revocation; endpoint trust-store removal is the endpoint's job).

## Impact

- `internal/gateway.CertMinter` (Rotate + named TTL const), `cmd/openshield-gateway`
  SIGHUP reload, `docs/decisions.md` D79. No proto/pipeline change.
- Proven with real certs: after `Rotate` to CA2, a re-minted leaf chains to CA2 and
  no longer verifies against CA1 (cache flushed); an invalid `Rotate` errors and
  leaves the minter working with CA1; `Rotate` is race-safe with concurrent `For`.
- NOT in scope (stated): CRL/OCSP for leaves; automated rotation scheduling; endpoint
  trust-store distribution/removal; multi-CA overlap trust on the gateway side.
  Respects D16, D60, D75.
