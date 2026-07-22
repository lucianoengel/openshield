# Design — wire OIDC into the access proxy

## Token for the user, cert for the device

The access proxy always runs under RequireAndVerifyClientCert, so a request already carries a DEVICE
certificate. ZT-2 adds the USER identity from a bearer token: when a verifier is configured, the
proxy requires and verifies the token and uses ITS subject+role for authorization, while the device
cert continues to gate the connection at the TLS layer. This is the BeyondCorp shape (user token +
device cert); composing both into one authorization decision is ZT-3. When no verifier is configured,
the behavior is exactly as before (cert identity), so wiring OIDC is purely additive.

## Fail closed, generic errors

The verifier already rejects `none`, algorithm confusion, wrong issuer/audience, and
expiry/not-before. The proxy adds: a missing token is 401 and an invalid token is 403, with generic
messages (no verifier or token detail leaked). The access proxy fails CLOSED on any identity error —
a Zero-Trust gate never admits on a failure.

## Static keys now, JWKS later

Keys load from a directory of `<kid>.pem` files (the filename is the kid a JWT references). A live
JWKS fetch would be cleaner operationally but is a network dependency AT THE GATEWAY CHOKEPOINT, so
it deserves its own timeout/failure design rather than being bolted on — noted as the follow-up. The
static wiring already enables SSO against a configured IdP key.

## Proven

An end-to-end test drives the real access proxy over mTLS: a valid finance token authorizes and
reaches the upstream, a missing token is 401, and a tampered token is 403 with the upstream never
reached. The mutation accepting an unverified token makes the tampered token succeed (200) — the test
fails. The key loader is tested for a valid dir, a non-PEM file, and an empty directory.
