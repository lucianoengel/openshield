## 1. Entity keying primitive

- [x] 1.1 Add `xdr.Store.LookupAny(ctx, value) (int64, bool, error)` — resolve an entity by alias VALUE
  across all kinds, creating nothing; not-found is `(0, false, nil)`, an error is only an infra error.
- [x] 1.2 Unit test `LookupAny` against real Postgres: a value registered under `user` resolves; a miss
  returns not-found **and leaves `entities`/`entity_aliases` row counts unchanged** (proves read-only);
  after `Link(device D, user U)` both `D` and `U` return the same id.
- [x] 1.3 Use `LookupAny` inside `RecordUnifiedAlert` before `Resolve(kind, value)`, so an alert keys onto
  an entity another domain already named; fall back to the existing resolve-or-create on a miss.
- [x] 1.4 Test the device⋈user keying: link `D`⋈`U`, record a unified alert for subject `U`, assert its
  `entity_id` equals the entity a `D`-subject alert resolves to. **Mutation:** remove the `LookupAny`
  call → the alert forks onto a new entity → the test must FAIL.

## 2. Decision → unified-alert projection

- [x] 2.1 New `internal/controlplane/decision_alerts.go`: `unifiedDomainFor(corev1.EventKind) (string, bool)`
  — total over the closed enum (file/USB→`dlp`; process-exec, ransomware, memory-injection, file-deleted
  →`hips`; network-flow, http-request, dns-query, smtp-message→`nips`; unspecified→not ok).
- [x] 2.2 `alertableAction(corev1.Action) bool` (everything except UNSPECIFIED and ALLOW) and
  `severityForDecision(action, confidence) string` = `Severity(confidence)` floored at `high` for the
  enforcement actions (BLOCK, DENY_EXEC, KILL_PROCESS, QUARANTINE_LOCAL, ENCRYPT_LOCAL, REDIRECT).
- [x] 2.3 Table-driven unit tests for 2.1/2.2 covering **every** member of both closed enums, so adding an
  enum member without extending the mapping is caught here rather than silently unmapped at runtime.
- [x] 2.4 `alertTitleFor(action, kind) string` built from the enum names ONLY. Test asserts the title
  contains neither `Decision.reason` text nor any event target field — the D10/D29 boundary test.
- [x] 2.5 `projectDecisionAlert(ctx, payload)`: decode the `Decision`; return early unless alertable; load
  the originating verified `event` row by `event_id` from `fleet_telemetry`; decode subject + kind; map
  the domain; call `RecordUnifiedAlert(domain, KindDevice, subject, severity, title,
  "decision:"+decision_id, decided_at)`.
- [x] 2.6 Add the `UnprojectedDecisions` counter (originating event missing / subject empty / domain
  unmapped) and export it through the existing metrics surface; test that it increments for a decision
  whose event was never persisted, and that no alert row is written in that case.

## 3. Wire into verified ingest

- [x] 3.1 Call `projectDecisionAlert` from `handleSigned` AFTER the telemetry transaction commits, for
  `kind == "decision"` only — never on the unverified `handle()` path (D44).
- [x] 3.2 Test that a projection failure leaves ingest untouched: force the alert write to fail, assert
  the decision is still persisted, the ingest outcome is still `ingestPersisted`, and a failure counter
  incremented (D38 derived-index discipline).

## 4. The acceptance test — real ingest, real Postgres

- [x] 4.1 End-to-end test through `handleSigned` with genuinely signed envelopes from one enrolled agent:
  publish `event(PROCESS_EXEC)` + `decision(KILL_PROCESS)`, then `event(DNS_QUERY)` + `decision(BLOCK)`,
  all carrying the SAME event subject. Assert two `unified_alerts` rows, one `entity_id`, domains
  `{hips, nips}`, severities at least `high`.
- [x] 4.2 **Mutation A:** key the alert by the producing `agent_id` instead of the event's subject → the
  two alerts land on different entities → 4.1 must FAIL.
- [x] 4.3 **Mutation B:** drop the `ACTION_ALLOW` filter → an ALLOW decision in the same test produces a
  row → the "no alert for ALLOW" assertion must FAIL.
- [x] 4.4 Test the ZT shape end to end: a gateway-style `event(HTTP_REQUEST)` whose subject is a USER
  identity already linked to a device, plus its deny `decision` → the alert lands on the LINKED entity,
  beside the endpoint domains' alerts, and `AlertsForEntity` returns all of them.

## 5. Gate and land

- [x] 5.1 `OPENSHIELD_REQUIRE_POSTGRES=1 make all` green locally (build, vet, lint, full test suite).
- [x] 5.2 Update the `unified-alerts` and `entity-model` capability specs via the change's delta specs at
  archive time; update `docs/architecture-roadmap.md` — XDR-2 increment 2 done, the remaining XDR-2 note
  retired, and XDR-4's "must read `unified_alerts`" precondition now satisfied.
- [x] 5.3 Commit with the ticket handle in the message (`XDR-2`), then archive the OpenSpec change.
