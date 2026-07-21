-- Peer-UEBA alerts (D54): a SERVER-SIDE DERIVATION, deliberately stored apart
-- from received telemetry (fleet_telemetry). A peer alert is not an agent-attested
-- message — it is the control plane's own detection that a subject is anomalous
-- RELATIVE TO ITS PEERS across the fleet. It is not the evidentiary ledger (D38);
-- it is a fleet-aggregate detection surface. The subject is pseudonymous (D23).
CREATE TABLE IF NOT EXISTS peer_alerts (
    id              BIGSERIAL PRIMARY KEY,
    subject_id      TEXT NOT NULL,
    risk_score      DOUBLE PRECISION NOT NULL,
    context_version TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS peer_alerts_subject_idx ON peer_alerts (subject_id);
