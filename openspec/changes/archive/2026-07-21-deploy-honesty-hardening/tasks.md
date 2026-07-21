# Tasks — deploy honesty + gateway hardening (D84)

## 1. Gateway systemd unit

- [x] 1.1 `deploy/systemd/openshield-gateway.service` — dedicated `openshield-gateway` user/group; empty CapabilityBoundingSet; NoNewPrivileges; ProtectSystem=strict; ProtectHome; PrivateTmp; StateDirectory=openshield-gateway (0700) holding OPENSHIELD_SIGNER_FILE + interception-CA files; network-capable; dev-default env.

## 2. install.sh

- [x] 2.1 Build + install the gateway binary + unit; `ensure_user openshield-gateway`.
- [x] 2.2 Remove `openshield-agent.service` from the `systemctl enable` line; add `openshield-gateway.service`; correct the operator messaging (agent is a deferred stub, not enabled).

## 3. Docs

- [x] 3.1 `docs/decisions.md` D84 + a Superseded/reframed entry: "Zero Trust oriented" (brief) is not delivered — the gateway authenticates no subject, so it is not a ZT enforcement point; it is not a NIPS.
- [x] 3.2 A one-line honest note in the README "what it does not claim" area (negated, doccheck-safe).

## 4. Proof (guards, each mutation-tested)

- [x] 4.1 **Test** `TestGatewayUnitIsolatesTheSecretHolder`: parse the gateway unit; assert dedicated user, NoNewPrivileges, empty CapabilityBoundingSet, ProtectSystem=strict, a StateDirectory.
- [x] 4.2 **Test**: install.sh installs + enables the gateway unit AND creates the gateway user AND does NOT enable the openshield-agent stub.
- [x] 4.3 doccheck passes on the README note.

## 5. Ship

- [x] 5.1 `openspec validate deploy-honesty-hardening --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| the installer re-enables the openshield-agent stub | `TestInstallerHardensGatewayAndDoesNotEnableStubAgent` |
| the gateway unit runs as root | `TestGatewayUnitIsolatesTheSecretHolder` |

THE VERDICT (D84): the stub agent is no longer enabled as a failing unit; the gateway — holder of the
signer and the interception-CA skeleton key — runs under its own isolated hardened unit like the engine
(D68); and the "Zero Trust oriented" brief line is reframed (the gateway authenticates no subject, so it
is not a ZT enforcement point and not a NIPS). NOT in scope: the real inline-blocking agent; ZT identity
at the proxy; packaged artifacts.
