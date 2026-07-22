# Design — dual credential

## Two credentials, two lookups

BeyondCorp authorizes on WHO (the user) and WHAT DEVICE. ZT-2 gave the user (token); ZT-3 adds the
device by resolving the client certificate's identity on every request and looking up device POSTURE
by THAT identity — because the agent publishes its own device's posture keyed by the device (SEC-12),
not by whatever user happens to be logged in. Risk stays keyed by the user (it is the user's
behavioral signal). The policy then sees `{role, risk}` from the user and `device_posture` from the
device, and a rule like `role == "finance" && device_posture.compliant` is a genuine dual check.

## Why the old lookup was wrong

ZT-2 looked up posture by the token's user subject. Posture keyed by the device never matched a user
subject, so under SSO the device posture was always absent — a posture-requiring policy would deny
everyone (or, if it did not require posture, ignore the device entirely). ZT-3's device-keyed lookup
is the fix: publishing posture for the USER does NOT satisfy a device requirement (proven), and a
valid user on an unattested device is denied.

## Backward compatible

With OIDC off (single-credential), the user IS the device cert, so `deviceID == userID` and the
posture lookup is unchanged — the pre-ZT-3 single-credential tests pass untouched.

## Proven

The test drives real mTLS with an OIDC finance token and a policy requiring finance role AND a
compliant device: no device posture → denied; posture published for the USER subject → still denied
(device-keyed); posture published for the DEVICE → allowed and the upstream reached. The mutation
reverting the lookup to the user subject makes the user-keyed posture wrongly admit.
