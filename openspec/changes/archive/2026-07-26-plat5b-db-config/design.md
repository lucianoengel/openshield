## Context

D262 typed the fields and derived the schema, with env → file → default. The owner's push is correct: that
is the layered-`.conf` model, and it does not survive a UI. The industry answer is a hard static/dynamic
split with the store authoritative for dynamic settings, plus revisions.

## Goals / Non-Goals

**Goals:** per-field scope; DB-authoritative dynamic tier; revisions with author, diff and rollback;
validation at save; live apply; secrets never stored.

**Non-Goals:** the UI itself; per-node dynamic values; staged rollout; secret management; gateway/agent.

## Decisions

### Scope is per field, and bootstrap is deliberately tiny

Bootstrap = what the process needs to *reach the database*: DSN, listen addresses, TLS material, the
config file path, and the location of credentials. Everything else is dynamic. The test that keeps it
honest is a bound on the bootstrap set: if it grows, the split has been abandoned by accretion.

### The database is the ONLY source for a dynamic field

Not "database above env". The moment env can shadow a dynamic setting, the console and the host can
disagree with no signal — precisely the failure that makes layered-file products painful, and it would
arrive through the door this design opened.

The cost is a real one, so it is paid explicitly rather than avoided: an operator who needs a single-host
override in an incident sets `OPENSHIELD_BREAKGLASS=<KEY>[,<KEY>...]` alongside the value. The override
then applies **and is reported** in the effective configuration as an override. Visible beats convenient;
silent is what we are refusing.

An env value for a dynamic field *without* break-glass is ignored and reported as ignored — not an error,
because an old unit file should not stop a server from booting, and not silent, because the operator
believes it is doing something.

### Revisions, not writes

`config_revisions` (author, note, at) + `config_changes` (revision, key, old, new) + `config_settings`
(current). Three tables rather than one because they answer three questions: what is in effect, who
changed it, and what did it change *from*.

Rollback creates a NEW revision restoring the old values rather than deleting history. An audit trail you
can rewind by erasing is not one.

### Validate at save, refuse the whole change

The same `Field` declarations validate a proposed value at the moment of the change, and one bad key
refuses the entire revision. Partial application would leave a deployment in a state no operator chose.

### Secrets are refused by the write path

A `KindSecret` field cannot be stored at all — not encrypted, not referenced-then-stored. Its value stays
in env or a file. This is Elastic's keystore split, and the property it buys is blunt: a dump of the
config database contains no credentials.

The honest cost, stated in the spec: setting a connector token still requires host access, so that part is
not UI-driven. Encrypting values in the database would fix the UX and trade it for "a database backup plus
a leaked master key is every credential", plus key rotation as a feature we would then owe.

### Live apply, or it is a config file with extra steps

A `Watcher` polls the max revision and swaps an immutable snapshot on change (atomic pointer swap, so a
reader never sees a half-applied revision). Periodic work then reads its parameters **per tick** instead of
capturing them at start — which is why `retain.DynamicLoop` takes an interval *function*, and why
`RunCorrelationLoop` takes a rule *provider* rather than a rule.

That is the expensive part of this ticket and the reason it is one ticket: shipping the store without it
would mean a UI that saves a value which does nothing until someone restarts the fleet.

## Risks / Trade-offs

- **A dynamic env value silently stops working** → reported at boot and in the effective output; the
  break-glass exists for the case that matters.
- **Polling the revision adds a query per interval** → one indexed `max(id)` read; cheaper than the
  correlation tick it rides alongside.
- **A snapshot swap mid-tick** → the snapshot is immutable and swapped atomically; a tick uses one
  consistent revision.
- **Rollback restores values, not behaviour** → a revision that was applied while a connector was
  unreachable is not undone by restoring the setting, and that is stated rather than implied.

## Migration Plan

Migration 036 is additive. With no rows, every dynamic field falls back to its declared default — which is
today's behaviour for anything not set — so a deployment that upgrades without writing settings keeps
working, except for dynamic values previously set in the environment, which are now reported as ignored.

## Open Questions

- Whether a future gateway/agent should read dynamic settings from the same store or receive them over the
  existing signed channel — the latter is likely, given they must not hold database credentials.
