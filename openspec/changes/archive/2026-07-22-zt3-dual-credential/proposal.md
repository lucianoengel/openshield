# ZT-3: dual-credential authorization (user token + device certificate)

## Why

ZT-2 resolves the USER identity from an OIDC token, but the DEVICE the user connects from was only
gating the TLS handshake — its posture was not composed into the authorization. Worse, device
POSTURE was looked up by the token's USER subject, but posture is published per DEVICE (the agent
reports its OWN device's posture, keyed by the device identity, SEC-12). So with SSO on, the device
posture lookup missed, and a policy could not require "a finance USER on a compliant DEVICE" —
BeyondCorp's core check. ZT-3 composes both credentials.

## What Changes

- **The device credential is resolved from the enrolled client certificate** on every request
  (dual-credential means BOTH a valid device AND, when OIDC is on, a valid user). An unenrolled
  device certificate is refused.
- **Device posture is keyed by the DEVICE certificate, not the user token** — posture is about the
  device the user connects from. A valid user on an UNATTESTED device is denied by a
  posture-requiring policy (the dual check: valid user AND compliant device), and posture published
  for a user's subject does not satisfy a device requirement.
- **Risk stays keyed by the USER** — risk is about the user's behavior. So the policy sees the
  user's role + risk and the device's posture, and can authorize on the combination.

## Impact

- Affected specs: `network-gateway`
- Affected code: `internal/gateway/access.go` (resolve device from cert, user from token,
  posture-by-device).
- Not in scope (stated): exposing the DEVICE identity string to the policy as its own field (would
  need a core.Context change; the device's POSTURE is the credential composed here — binding a user
  to a SPECIFIC device id is a follow-up); the OIDC-off (single-credential) path is unchanged (device
  cert is both device and user); ZT-1 hardware attestation of the posture (the posture is still
  self-reported, hardened separately).
