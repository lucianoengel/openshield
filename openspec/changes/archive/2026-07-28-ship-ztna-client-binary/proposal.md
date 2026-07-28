# The ZTNA client is complete, tested, and has no way to be run

## Why

`internal/ztna` is the ENDPOINT half of Zero-Trust access (ZT-4). It brokers an application's HTTP
traffic to the access proxy while presenting the DEVICE's certificate, so a connection is authorized
by device identity rather than by whatever the application happened to configure. Applications point
at it with the ordinary `HTTP_PROXY` convention — no application changes, no root, no kernel
interface.

It refuses to start without a device identity, binds loopback only, never falls back to an
unauthenticated or direct connection when the broker refuses, and does not follow redirects off the
authorized path. Four tests in `internal/gateway` drive it against a real access proxy.

**No binary builds it, and no configuration setting exists.** An operator has no way to run it. The
capability spec describes it, the roadmap counts it as shipped (D249), and the README had to be
corrected in D343 to say "the endpoint-side client is built and not yet shipped as a binary" — a
sentence that exists only because of this gap.

Same shape as the SMTP connector in D342, and found the same way: a symbol with no non-test caller.

## What Changes

- A new `openshield-ztna-client` binary: reads the device certificate, the CA to verify the broker
  against, the broker URL and the loopback listen address, and serves the local proxy.
- Configuration settings for each, declared in the typed config so a malformed value is refused at
  startup rather than producing a broker that runs and cannot connect.
- The startup line states what the client is NOT — an access broker, not a network jail — because the
  name invites the stronger reading and the library's own doc comment says so.
- The README line about it not being shipped as a binary is removed, because it stops being true.

## Impact

- Affected specs: `ztna-client`
- Affected code: `cmd/openshield-ztna-client` (new), `internal/config`
- No proto change, no migration, no new dependency. The library is unchanged.
- Nothing else is affected: this adds a binary that nothing else links.

## Honest limits, carried from the library and restated where an operator will see them

- **It brokers access; it does not PREVENT bypass.** An application with a direct route to the
  internal network can still take it. Commercial ZTNA clients enforce the path with routing and
  firewall rules; OpenShield has the mechanism (the NIPS-1 transparent inline plane) and wiring it
  here is a separate ticket.
- **HTTP(S) via the proxy convention only** — no CONNECT tunnelling to arbitrary ports, no SOCKS, no
  split DNS.
- **It is not an enrolment tool.** The device certificate has to exist already, from
  `openshield-provision cert`.
