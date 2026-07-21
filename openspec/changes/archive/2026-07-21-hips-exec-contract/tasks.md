# Tasks — HIPS exec contract + action expansion (D109)

## 1. Contract

- [x] 1.1 Proto: ProcessSubject, EVENT_KIND_PROCESS_EXEC, Event.process target; ACTION_DENY_EXEC/KILL_PROCESS; regenerate.
- [x] 1.2 Deliberate closed-set edits: validate.go knownActions, policy actionNames, schema_test action list; policy.buildInput exposes process fields.

## 2. Proof (fitness, D69 pattern)

- [x] 2.1 **Test**: an exec Event flows the UNCHANGED dispatcher → behavioral policy → KILL_PROCESS → audited → existing TargetedEnforcer via pid; ProcessSubject has no memory/content field; both verbs validate; action-enum tests updated deliberately.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D109.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| check | result |
|---|---|
| exec Event through unchanged core.Dispatcher → KILL_PROCESS decision, audited | pass (fitness) |
| existing TargetedEnforcer carries it out via target=pid | pass (no new interface) |
| ProcessSubject exposes no memory/content field | pass (boundary) |
| both new verbs validate under the closed set; count test updated deliberately | pass (T1 discipline) |
