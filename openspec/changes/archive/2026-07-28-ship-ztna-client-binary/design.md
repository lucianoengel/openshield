# Design

## The binary is thin on purpose

Everything that decides anything already lives in `internal/ztna`: refusing without an identity,
refusing a non-loopback bind, not following redirects, surfacing a broker refusal rather than falling
back. The binary reads configuration, builds the TLS material, and calls `ListenAndServe`.

That split is why the library's four tests are worth anything — they exercise the behaviour against a
real access proxy from the gateway package. A binary that re-implemented any of those decisions would
put them where those tests do not reach.

## Failing to start is the correct outcome

Every configuration problem here is fatal, and deliberately so. A ZTNA client that starts without a
device certificate would forward traffic unauthenticated while looking like protection, which is worse
than not running: the application keeps working, and nobody learns the device identity was never
presented. `ErrNoDeviceIdentity` already encodes that, and the binary must not soften it.

The same applies to a non-loopback listen address. The library refuses it because a broker bound to a
routable interface is a relay anyone on the LAN could drive with THIS DEVICE's identity — a
credential-sharing service wearing a security product's name.

## What the startup line has to say

The library's doc comment states the limit plainly: it brokers access, it does not prevent bypass. An
operator reading a README once will not remember that when an application later reaches the network
directly, so the process says it every time it starts.

This follows the same discipline as the SMTP capture listener (not an MTA, no TLS) and the plaintext
syslog stream (sender not authenticated): a limit that lives only in documentation is a limit that
will be discovered in production.

## Configuration

Four settings, all bootstrap — the client cannot reach a database, and each is needed before it can do
anything:

- the broker URL,
- the device certificate and key,
- the CA bundle to verify the broker,
- the loopback listen address (defaulted, since the whole point is a fixed local endpoint applications
  are configured against).

Typed and validated, so a wrong path fails at startup with the field named rather than at the first
request with a TLS error.

## What is deliberately not built

An enrolment flow. The device certificate comes from `openshield-provision cert`, which exists; adding
a second way to obtain one here would be a second trust path to keep correct.
