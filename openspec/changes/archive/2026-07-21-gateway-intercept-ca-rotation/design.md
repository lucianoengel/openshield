## Context

`CertMinter` (D75) holds the interception CA and mints (and caches) an Ed25519 leaf
per SNI host, signed by that CA. The CA is loaded once at startup from PEM. The
minimal PKI (D60) has no revocation and no rotation — stated limits, but the
interception CA's power (impersonate any site) makes "we can never replace it
without a restart" a sharper gap than for the fleet CA.

## Goals / Non-Goals

**Goals:**
- Replace the interception CA at runtime, safely, without restarting.
- Never serve a leaf signed by a rotated-away CA.
- State honestly what leaf and CA revocation mean in the minimal PKI.

**Non-Goals:**
- CRL/OCSP; automated rotation scheduling; endpoint trust-store distribution;
  gateway-side multi-CA overlap trust.

## Decisions

**Validate-then-atomic-swap-and-flush, fail-safe.** `Rotate` parses and validates
the new CA cert+key BEFORE taking the lock to swap. If the PEM is invalid it returns
an error and the minter keeps the working CA — a bad rotation (fat-fingered file, a
half-written reload) must not break interception or silently disable it, because a
minter that can no longer mint would fail every intercepted handshake. Only a valid
new CA is installed. The swap and the cache flush happen together under the mutex:
every cached leaf was signed by the old CA, so after the swap the cache is CLEARED
and the next handshake re-mints under the new CA. A stale leaf chaining to a
rotated-away (possibly compromised) CA is never served.

**The short leaf TTL is the leaf-revocation mechanism.** Interception leaves are
ephemeral: minted per host, valid ~24h, cached only in memory. There is nothing to
revoke at the leaf level — a leaked leaf expires within a day and a rotation flushes
it immediately. So the minimal PKI needs no CRL/OCSP for leaves; the TTL IS the
bound. This is now a named const with the reasoning next to it, not an incidental
number.

**CA revocation is rotate-away or remove-to-tunnel.** To revoke the interception CA
itself: `Rotate` to a fresh CA (the old CA's key is discarded from the minter), or
drop the CA config entirely so interception turns off and everything tunnels (D74).
The endpoint side — removing the old CA from managed trust stores so it can no
longer impersonate — is the endpoint's configuration, out of the gateway's scope,
and stated as such (D16: custody and trust distribution are the deployer's).

**SIGHUP reloads the CA in place.** The gateway reloads the CA files and calls
`Rotate` on SIGHUP, so an operator replaces the CA without dropping live
connections. A reload error is logged and the old CA keeps serving (same fail-safe).

## Risks / Trade-offs

- **Rotation is only half the story.** The gateway can stop signing with a
  compromised CA, but endpoints keep trusting it until their trust stores are
  updated — the real revocation is at the endpoint. Stated plainly (D16), not
  papered over: the gateway change bounds the gateway's behaviour, not the fleet's
  trust.
- **In-flight handshakes during a swap** may still use the old CA (the swap is
  atomic per-`For` call). Acceptable: the window is a single handshake, and both CAs
  are valid during a planned overlap. Noted.
