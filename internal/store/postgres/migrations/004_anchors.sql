-- External anchoring (T-019).
--
-- A witnessed checkpoint of the ledger head: at some moment the latest entry was
-- `sequence` with `hash`, attested by a witness key in a different trust domain
-- than the agent. Because the chain is linear, the head hash commits to the
-- whole prefix, so no Merkle inclusion data is needed.
CREATE TABLE IF NOT EXISTS anchors (
    sequence    BIGINT NOT NULL,
    hash        BYTEA NOT NULL,
    witness_sig BYTEA NOT NULL,
    anchored_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS anchors_seq_idx ON anchors (sequence);
