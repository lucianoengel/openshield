## Context

Enrollment binds an agent_id to a public key. The upsert made that binding overwritable by
anyone with a fresh token — the identity foundation the whole verified-telemetry story rests
on.

## Goals / Non-Goals

**Goals:** enrollment cannot overwrite an existing key or un-revoke; the fix is atomic.

**Non-Goals:** token→id binding at issuance; an operator rotation flow.

## Decisions

**ON CONFLICT DO NOTHING + refuse on zero rows.** The insert is atomic; a zero row count
means the id already exists, so enrollment returns ErrAgentExists. This refuses both the
key-overwrite hijack and the un-revoke, in one predicate, race-safe (two concurrent enrolls
of the same id: one inserts, the other sees zero rows).

**Do not consume the token on a rejected hijack.** The token stays valid so a legitimate
holder can still enroll a fresh id — only the hijack of an existing id is refused. (A
stronger token→id binding is a follow-up.)

**Re-enrollment is an operator action.** Rotating an agent's key means an operator revokes
or deletes the old identity first, then the agent enrolls — an explicit, audited path, not
an implicit upsert a stolen token can trigger.

## Risks / Trade-offs

- **A generic token can still enroll one new agent** — that is its purpose. The bug was
  hijacking an EXISTING id; that is closed.
- **Key rotation now needs an operator step.** Acceptable: silent key replacement was the
  vulnerability.
