# Tasks — SIEM-6 alert lifecycle

- [x] `Severity(risk)` + `severityFloor(label)` pure functions (inclusive boundaries).
- [x] Surface Severity on PeerAlert and Incident.
- [x] Migration 016: peer_alerts.acknowledged_at / acknowledged_by + partial index; count test 15->16.
- [x] `AcknowledgeAlert(id, operator)` — first-ack-wins, phantom vs already-acked disambiguation.
- [x] `POST /alerts/ack` handler — operator identity from client cert; mounted under the operator gate.
- [x] AlertFilter: MinSeverity (risk-floor translation, stronger-of-two) + UnacknowledgedOnly; parse + validate.
- [x] Tests: severity boundaries; ack first-wins + phantom + queue + min_severity.
- [x] Mutations: severity boundary >= -> >; first-ack-wins guard dropped; unacknowledged filter dropped.
- [x] `make all` clean.
- [x] docs/decisions.md D135; sync spec; archive; commit; push; memory.
