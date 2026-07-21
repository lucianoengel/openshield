# Tasks — engine → fleet telemetry (D80)

## 1. Engine projection

- [x] 1.1 `internal/engine`: define an engine-local `Projector` interface (PublishEvent + PublishDecision); add optional `telemetry Projector` + `logger` fields; `SetTelemetry(Projector)`. Default logger to slog.Default() when nil.
- [x] 1.2 `Process`: after the Decision is recorded, if `telemetry != nil` publish the Event (as-is) and the Decision, best-effort (log errors, never fail Process).

## 2. Binary

- [x] 2.1 `cmd/openshield-engine`: when `OPENSHIELD_NATS_URL` + `OPENSHIELD_ENROLL_URL` are set, generate an identity, `enroll.Enroll`, connect NATS, build a `SignedPublisher` (optional `OPENSHIELD_SEQ_FILE`), and `SetTelemetry` — mirroring the gateway; else projection off.

## 3. Proof (guards, each mutation-tested)

- [x] 3.1 **Test**: FAKE Projector. A file event Process projects exactly one Event + one Decision; the projected Event retains the FilesystemSubject path.
- [x] 3.2 **Test**: with no projector configured, NOTHING is projected (opt-in default).
- [x] 3.3 **Test**: a projection error does not fail Process, and the local ledger still recorded the decision.

## 4. Docs, ship

- [x] 4.1 `docs/decisions.md` D80: the engine projects real detections (Event + Decision) to the control plane — boundary-safe, opt-in, best-effort — closing the engine-to-fleet disconnect; the file path is projected as file identity; the recurring self-verification integration gap closed at the fleet boundary.
- [x] 4.2 `openspec validate engine-fleet-telemetry --strict`; `make all` + `-race`; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| project even when the projector is nil | `TestEngineTelemetryOffByDefault` |
| skip the Event projection | `TestEngineProjectsDetection` |

THE VERDICT (D80): the endpoint engine projects real detections (Event + Decision) to the control
plane — opt-in, additive, best-effort — so fleet visibility, peer-UEBA and the dead-man's-switch now
operate over real endpoint detections, not only the simulator. The engine-to-fleet disconnect the audit
surfaced is closed. NOT in scope: retiring the simulator; path redaction; ClassificationSummary.
