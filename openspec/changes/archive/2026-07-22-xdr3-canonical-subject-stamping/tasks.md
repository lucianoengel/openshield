# Tasks

## 1. Engine stamping + validation
- [x] 1.1 `Engine.subject string` + `SetSubject(agentID string)` → `e.subject = pseudonym.Of(agentID)`.
- [x] 1.2 In `Process`, when `e.subject != ""`: stamp `ev.Subject` (canonical pseudonym) if the event has
  no subject, stamp `ev.ObservedAt` (engine clock) if unset, then `core.ValidateEvent(ev)` and RETURN the
  error if invalid — before dispatch. Unconfigured (`e.subject == ""`) → unchanged (no stamp, no validate).

## 2. Binary wiring
- [x] 2.1 `cmd/openshield-engine`: `eng.SetSubject(agentID)` from the enrolled agent identity, so real
  fanotify/execaudit events carry the enrolled device pseudonym (only when an identity is configured).

## 3. Tests
- [x] 3.1 A configured engine processes a connector-style event (target, no subject, no observed_at) →
  it is stamped and `ValidateEvent` passes; the stamped subject == `pseudonym.Of(agentID)`.
- [x] 3.2 The canonical join: `TestEngineStampsCanonicalSubject` asserts the stamped subject ==
  `pseudonym.Of(agentID)` — the SAME key the gateway (D87) and the entity model (D195) resolve by — so
  it resolves to the same XDR entity. Proven by composition with D195's real-Postgres canonical-join test
  (not duplicated here).
- [x] 3.3 A still-invalid event (no target) through a configured engine → rejected with an error.
- [x] 3.4 An UNCONFIGURED engine processes a subject-less event → unchanged (still decides, no rejection)
  — the existing engine tests remain green.

## 4. Mutation guards
- [x] 4.1 Make `Process` skip the subject stamp (stamp observed_at only) → the stamp+validate test (3.1)
  FAILs (no subject → ValidateEvent errors). Revert.
- [x] 4.2 Make `Process` NOT return the ValidateEvent error (swallow it) → the invalid-event test (3.3)
  FAILs (a no-target event is processed instead of rejected). Revert.

## 5. Record + close
- [x] 5.1 `docs/decisions.md`: new entry (D196) — XDR-3 canonical subject stamping; closes the
  defined-but-never-called ValidateEvent gap; engine-attributes/connectors-stay-dumb; gated backward-compat;
  canonical join to XDR-1.
- [x] 5.2 `docs/architecture-roadmap.md`: mark XDR-3 shipped; note XDR-2/4 next.
- [x] 5.3 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green; `GOOS=windows/darwin go build ./...`;
  `go test ./internal/doccheck/`; sync the delta into `openspec/specs/endpoint-engine/spec.md`.
