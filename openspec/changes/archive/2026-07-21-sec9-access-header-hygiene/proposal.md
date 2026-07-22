## Why

SEC-9 (P2). The access reverse proxy forwarded the original client request WITHOUT stripping
client-supplied identity/forwarding headers (`X-Authenticated-User`, `X-Forwarded-*`), and
injected NO trustworthy verified-subject header — so a backend could be fed a SPOOFED identity
(a client sets `X-Authenticated-User: admin`) and could not consume the real (pseudonymous)
one. Hop-by-hop stripping existed on the egress path only.

## What Changes

- `AccessProxy` strips client-supplied identity/forwarding headers before proxying
  (`sanitizeIdentityHeaders`) — including `X-OpenShield-Subject`, so a client cannot pre-set
  the trusted header — and injects the gateway-authoritative `X-OpenShield-Subject` = the
  verified pseudonymous subject (D23).

## Capabilities

### Modified Capabilities
- `network-gateway`: the access proxy sanitizes inbound identity headers and injects a
  verified subject.

## Impact

- `internal/gateway/access.go`; `docs/decisions.md` D121.
- Proven (real TLS + client cert): a client's spoofed `X-Authenticated-User` and pre-set
  `X-OpenShield-Subject` do NOT reach the backend; the backend receives `X-OpenShield-Subject`
  = the verified cert pseudonym (not the spoof), and the client's spoofed `X-Forwarded-For`
  value does not survive the chain. Guards mutation-tested (don't-strip; don't-inject).
- NOT in scope (stated): SIGNING the injected subject header (a backend on the same trust
  domain trusts the gateway; cross-domain header signing is a follow-up); normalizing SrcIP on
  the access path (the access handler stores host:port vs the egress split — a small cleanup
  follow-up).
