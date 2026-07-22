# Design — metrics auth + bind guard

## Constant-time bearer token

The token check compares the full `Authorization` header against `"Bearer " + token` with
`subtle.ConstantTimeCompare` (and a length pre-check), so the token is not recoverable by timing and
a missing scheme, wrong token, or absent header all return 401. It is opt-in via
`OPENSHIELD_METRICS_TOKEN`, so the loopback dev default is unchanged.

## Warn, don't forbid

Refusing to bind a non-loopback metrics address would fight operators who front the endpoint with
their own network controls. Instead the server WARNS loudly when the address is reachable off-host
AND no token is set — the dangerous combination. `IsNonLoopbackBind` treats an unspecified host
(all interfaces), a routable IP, or a non-`localhost` hostname as exposed, and loopback IPs /
`localhost` as safe. The warning names the fix (bind loopback or set a token).

## Proven

The token wrapper is tested across no-token / wrong-token / missing-scheme (all 401) and the exact
token (200, handler reached); the mutation dropping the compare admits every request (the 401 cases
fail). The bind guard is tested over a table of exposed vs loopback addresses.
