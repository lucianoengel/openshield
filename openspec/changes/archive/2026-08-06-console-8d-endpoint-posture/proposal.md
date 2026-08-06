# CONSOLE-8d · The endpoint's device posture

## Why

Only `cmd/openshield-fleet-agent` — the fleet SIMULATOR — called `posture.Publish`. The gateway's
`PostureStore` was therefore fed exclusively by simulated hosts.

D85 states that **a device with NO posture published is UNTRUSTED**. So a deployment that turned the
tamper-lockout on **denied every real endpoint and admitted only the simulation**. A control that refuses
everything is as useless as one that refuses nothing, and it fails in the direction that gets it switched
off.

The existing integration coverage asserted the gateway's posture SUBSCRIPTION was active. That is the
receiver. Nothing proved a producer existed.

Separately, `selfVerify` in the engine already answered "are my installed files the ones that were
published?" (PLAT-6 inc 3) — and only ever wrote a log line, **on the host that may itself be
compromised**. The answer never became a fleet-wide fact.

## What Changes

- `openshield-engine` publishes signed device posture on an interval, under `pseudonym.Of(agentID)`.
- The report carries **binary integrity**, re-checked each cycle rather than cached at startup.
- Opt-in via a per-agent signing key; a configured-but-unusable key is fatal rather than degraded.
- An endpoint with no key says at startup that a posture-requiring gateway will deny it.

## Impact

- Affected specs: `device-posture`.
- No proto change, no migration. Off unless a key is configured.

## Deliberately NOT in this increment

TPM attestation (`CONSOLE-8e`) stays simulator-only. It needs a TPM and is genuinely VM-gated; folding it
in here would put an untestable path in the same commit as a tested one.
