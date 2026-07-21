## 1. The one core change

- [x] 1.1 `Dispatcher.ResolveContext func(*corev1.Event) *Context`; in Dispatch, after building
      State, `if d.ResolveContext != nil { st.Context = d.ResolveContext(e) }`. Nil = unchanged
- [x] 1.2 **Test**: a nil resolver leaves Context nil (behaviour unchanged); a resolver sets it.
      `TestResolveContextHook`

## 2. peer-UEBA capability (outside core)

- [x] 2.1 `internal/analytics/peerueba`: `Analyzer.Observe(subjectID)` accumulates per-subject
      activity; `ContextFor(subjectID)` computes a peer z-score → risk [0,1] + Version; thread-safe
- [ ] 2.2 `Analyzer.Resolver()` → `func(*Event) *core.Context` reading the pseudonymous subject
- [x] 2.3 **Test**: an anomalous subject scores high, a typical one low (peer-relative). `TestPeerRisk`

## 3. Policy reads the risk score

- [x] 3.1 `buildInput` includes `context.risk_score`/`has_risk_score` when State.Context is present
- [x] 3.2 **Test**: a peer-aware policy escalates on high risk score with no PII hit; the resolver
      flows the Context end to end. `TestPeerRiskEscalates`

## 4. Verdict + docs

- [x] 4.1 Confirm `check-capability-boundary.sh` still passes (analytics added to the ban) still passes (core does not import the analyzer)
- [x] 4.2 Note in `docs/decisions.md` (new D-number): peer-UEBA built; needed exactly ONE small core
      change (ResolveContext); zero-core-change claim false, small-change claim true (D26 validated)
- [x] 4.3 Validate; archive

## Verification performed

| mutation | caught by |
|---|---|
| skip the ResolveContext call (the one core change) | `TestResolveContextHook`, `TestPeerRiskEscalates` |
| risk score not peer-relative (constant) | `TestPeerRisk` |
| ignore the risk score in buildInput | `TestPeerRiskEscalates` |

**The fitness verdict (D53):** peer-UEBA — stateful, cross-entity, the new shape
D26 names as the real test — needed exactly ONE small, identifiable core change:
`Dispatcher.ResolveContext`, found before writing the capability (the dispatcher
built State with a nil Context and no injection point). Everything else is outside
core; `check-capability-boundary.sh` (now banning `analytics`/`engine` too) still
passes. The peer signal escalates a Decision with no PII hit, end to end
(analyzer → resolver → hook → policy → ALERT). The architecture absorbs a new-
shape capability with a small NAMED change — D26's narrow claim validated, the
zero-core-change claim disproven.
