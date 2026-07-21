## Why

The audit's remaining ship-blockers are deploy honesty-drift and an unhardened
gateway: (1) `install.sh` ENABLES `openshield-agent.service`, but the agent is a STUB
that `os.Exit(2)`s (the deferred inline-blocking component, D49/D62) — so systemd
loops it as a failed unit. (2) The gateway holds the ledger signer AND the
interception-CA skeleton key (D75) AND its NATS identity, yet unlike the engine (D68)
it has no systemd unit and no isolation. (3) The brief's "Zero Trust oriented" is not
delivered — the gateway authenticates no subject (the network subject is
`sha256(src-IP)`), so it is not a ZT enforcement point.

## What Changes

- `install.sh` stops enabling the stub agent (keeps installing its unit, disabled),
  with corrected messaging; and it creates the `openshield-gateway` user, builds +
  installs the gateway binary + unit, and enables it.
- `deploy/systemd/openshield-gateway.service` — hardened like the engine (dedicated
  non-login user, empty CapabilityBoundingSet, NoNewPrivileges, ProtectSystem=strict,
  ProtectHome, PrivateTmp, StateDirectory=openshield-gateway holding the signer + the
  interception-CA files); network-capable (it listens and reaches Postgres/NATS).
- A Superseded/reframed decision + a one-line README note: the network gateway is
  content-inspection egress DLP, NOT a NIPS or a ZT enforcement point (identity-aware
  authz is roadmap, not built).

## Capabilities

### Modified Capabilities
- `packaging`: the gateway unit is isolated and installed; the stub agent is no
  longer enabled.
- `doc-consistency`: the network gateway's NIPS/ZT scope is stated honestly.

## Impact

- `deploy/install.sh`, new `deploy/systemd/openshield-gateway.service`,
  `internal/packaging` guards, `docs/decisions.md` D84 + Superseded, a README note.
- Proven by the packaging tests: the gateway unit isolates its secret-holder; the
  installer installs+enables the gateway and its user and does NOT enable the stub.
- NOT in scope (stated): building the real inline-blocking agent (D49); ZT identity at
  the proxy (roadmap); packaged .deb/.rpm (still source-build). Respects D45/D68,
  D49/D62, D75, D16, D37.
