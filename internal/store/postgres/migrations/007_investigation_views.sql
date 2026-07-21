-- Investigation view accountability (T-013 seam, D20).
--
-- Who VIEWED an investigation, recorded by the write-capable control plane when
-- it serves one. NOT the forward-secure ledger — no hash chain, no signatures; a
-- compromised control plane could alter it — and the viewer is self-asserted (an
-- OS identity, labelled unauthenticated) until operator authentication exists.
CREATE TABLE IF NOT EXISTS investigation_views (
    id             BIGSERIAL PRIMARY KEY,
    viewer         TEXT NOT NULL,           -- labelled "unauthenticated:<os-user>" until operator authn
    subject_filter TEXT NOT NULL DEFAULT '',
    event_id       TEXT NOT NULL DEFAULT '',
    viewed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS investigation_views_event_idx ON investigation_views (event_id);
CREATE INDEX IF NOT EXISTS investigation_views_viewer_idx ON investigation_views (viewer);
