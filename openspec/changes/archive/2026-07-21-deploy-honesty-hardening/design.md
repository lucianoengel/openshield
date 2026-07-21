## Context

`install.sh` builds and installs the units, creating dedicated users for the worker
and engine (D68) but not the gateway, and its `systemctl enable` line includes
`openshield-agent.service` — a stub that exits 2 (D62). The engine got a hardened,
dedicated-user unit (D68) precisely because it holds the signer key; the gateway holds
the signer AND the interception-CA private key (D75) with none of that isolation.

## Goals / Non-Goals

**Goals:** don't run the stub; isolate + install the gateway like the engine; state the
ZT/NIPS scope honestly.

**Non-Goals:** building the real agent (D49); ZT identity at the proxy; packaged artifacts.

## Decisions

**Don't enable a unit whose binary exits 2.** The agent is the deferred inline-blocking
component (D49); its `cmd` is an honest stub (D62). Enabling its unit makes systemd run
a guaranteed-failing service — noise that masks real failures. `install.sh` keeps the
unit file installed (so a future real agent drops in) but removes it from the enable
line, and the operator note says plainly it is deferred, not "enabled but not started".

**Isolate the gateway like the engine (D68), because it holds more secrets, not fewer.**
The gateway holds the ledger signer AND — when interception is on — the interception-CA
private key, a skeleton key that can impersonate any site (D75). It therefore gets the
same dedicated-non-login-user + hardened-unit treatment the engine got: empty
CapabilityBoundingSet, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp,
and a 0700 StateDirectory owned by the gateway user holding the signer state and the CA
files. It keeps network access (it is a proxy — it listens and dials); network denial is
the worker's role (D35), not the gateway's. Host root still defeats at-rest protection
(D16); this closes the wrong-user erosion, matching the engine.

**State the ZT/NIPS scope, do not let the brief's vocabulary overclaim.** The brief lists
"Zero Trust oriented"; the gateway authenticates no subject (its subject is a hashed
source IP), so it is not a ZT enforcement point, and it inspects only HTTP(S) it is
configured to proxy, so it is not a NIPS. A Superseded/reframed decision and a negated
README note record this, guarded by doccheck's overclaim check (D37) — the note is honest
(what it is NOT), so it passes.

## Risks / Trade-offs

- **The gateway unit ships dev defaults** (a localhost DSN, a placeholder redirect URL)
  like the engine unit; a real deployment overrides them. Consistent with the existing
  units, noted.
- **Leaving the agent unit installed-but-disabled** could confuse an operator who enables
  it manually and hits exit 2. The unit's own comment and the installer note say it is a
  deferred stub; a stronger guard (the unit refusing to run) is a noted follow-up.
