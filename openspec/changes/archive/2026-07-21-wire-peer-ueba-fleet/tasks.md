# Tasks — wire peer-UEBA into the fleet telemetry stream

## 1. Store

- [x] 1.1 Migration `009_peer_alerts.sql`: `peer_alerts(id, subject_id, risk_score, context_version, detected_at)`.
- [x] 1.2 Bump the migration-count assertion in `postgres_test.go` to 9.

## 2. Control-plane wiring

- [x] 2.1 `Server` gains `analyzer *peerueba.Analyzer`, `PeerRiskThreshold float64`, and a per-subject cooldown map; enabled only when the analyzer is set (off by default).
- [x] 2.2 A constructor/option to enable it (e.g. `EnablePeerUEBA(threshold, cooldown)`), documented as the D23 consent/DPIA decision.
- [x] 2.3 `handleSigned`: AFTER verify+persist, if enabled and kind==`event`, decode the event, `Observe(subject)`, evaluate `ContextFor`, and record a peer alert above threshold subject to the cooldown.
- [x] 2.4 `recordPeerAlert` inserts into `peer_alerts`; add a `PeerAlerts` atomic counter.

## 3. Tests (guards, each mutation-tested)

- [x] 3.1 **Test**: an enabled server, fed a verified outlier over embedded NATS, records exactly one peer alert for the outlier subject and none for a typical subject.
- [x] 3.2 **Test**: unverified telemetry (bad signature) records NO peer alert and does not move the baseline.
- [x] 3.3 **Test**: the default (disabled) server records no peer alert.
- [x] 3.4 **Test**: many above-threshold events from one outlier yield one alert (cooldown), not one per event.

## 4. Live fleet e2e

- [x] 4.1 `deploy/fleet-e2e.sh`: enable peer-UEBA on the server, drive one agent as an outlier, assert a `peer_alerts` row exists for its subject and a typical agent produces none.

## 5. Boundary, docs, ship

- [x] 5.1 Confirm `check-capability-boundary.sh` still passes (controlplane→analytics is allowed; core is still clean).
- [x] 5.2 `docs/decisions.md` D54: peer-UEBA's real home is the control plane (cross-fleet); the fleet seam produces investigations and never controls agents (D14); the endpoint Resolver (D53) remains the core seam.
- [x] 5.3 `openspec validate wire-peer-ueba-fleet --strict`; `make all`; `openspec archive wire-peer-ueba-fleet --yes`; fix TBD Purpose; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| skip the cooldown check (alert every event) | `TestPeerAlertCooldown` |
| alert regardless of the risk threshold | `TestPeerAlertOnVerifiedOutlier` (typical subjects would alert) |
| observe/alert even when peer-UEBA is disabled | `TestPeerDisabledByDefault` (nil-analyzer crash on the disabled path) |
| observe BEFORE verification (unverified moves the baseline) | `TestPeerAlertIgnoresUnverified` |

peer-UEBA now runs server-side over the VERIFIED fleet stream: an outlier subject
raises exactly one peer alert (cooldown), a typical subject none, unverified
telemetry moves no baseline, and the default control plane records nothing
(off-by-default, D23). It OBSERVES — no message is sent to any agent (D14).
