## Why

SEC-2 (P0). `Enroll` used `ON CONFLICT (agent_id) DO UPDATE SET public_key = …, revoked_at =
NULL`. Any valid fresh enrollment token could overwrite ANY existing agent's public key —
then sign "verified" telemetry as that agent (the replay guard is moot: pick a large
sequence) — and could UN-REVOKE a revoked agent. This makes enrollment refuse to overwrite
an existing identity.

## What Changes

- `Enroll`: `ON CONFLICT (agent_id) DO NOTHING` + refuse (new `ErrAgentExists`) when the id
  already exists, WITHOUT consuming the token. Re-enrollment becomes an explicit, audited
  operator action (revoke/delete first).

## Capabilities

### Modified Capabilities
- `agent-identity`: enrollment records a NEW identity and cannot overwrite or un-revoke.

## Impact

- `internal/controlplane/identity.go`; `docs/decisions.md` D114.
- Proven (Postgres): a legitimate agent enrolls; an attacker with a DIFFERENT valid token
  cannot re-enroll that id with their key (ErrAgentExists), and the victim's key still
  verifies telemetry while the attacker's does not; a revoked agent cannot be un-revoked by
  re-enrollment and stays revoked. Guards mutation-tested: **restoring `DO UPDATE` fails the
  test**; dropping the existing-agent refusal fails it.
- NOT in scope (stated): binding a token to a specific agent_id at issuance (a stronger model
  — a token can only enroll its designated id; noted as a follow-up); an operator
  re-enrollment/rotation flow (revoke-then-enroll works today). The token is NOT consumed on
  a rejected hijack, so a legitimate holder can still enroll a fresh id.
