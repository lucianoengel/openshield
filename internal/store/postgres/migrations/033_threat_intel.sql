-- SOAR-5: the server-side IOC store, shared with the inline network engine.
--
-- NIPS-2's feed lives in the GATEWAY's memory, parsed from an operator file. The control plane held no
-- indicators at all, so SOAR-4's `enrich` step could only assemble local context and said so in its own
-- comment. This is where threat intel lands so an incident can be enriched with it.
--
-- SNAPSHOT SEMANTICS, deliberately: an ingest REPLACES the named feed's rows rather than appending. A
-- feed is what its publisher currently asserts. Append-only would mean a taken-down C2 domain stays
-- flagged forever and a withdrawn false positive can never be withdrawn — the store would only ever grow
-- and only ever get less trustworthy. The feed column is part of the key so one publisher's snapshot
-- never erases another's.

CREATE TABLE IF NOT EXISTS ioc_indicators (
    kind       TEXT NOT NULL,   -- domain | ip | cidr | uri (nips.Kind*)
    value      TEXT NOT NULL,
    feed       TEXT NOT NULL,   -- which feed asserted it — provenance an analyst can act on
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, value, feed)
);

-- The materialization read: build the matcher from every feed's indicators.
CREATE INDEX IF NOT EXISTS ioc_indicators_feed_idx ON ioc_indicators (feed);

-- Feed provenance: WHICH feed and WHICH VERSION of it asserted what is live. The digest is over the
-- feed's exact bytes — the same bytes the signature covers — so "which snapshot is loaded" is answerable
-- without keeping the file.
CREATE TABLE IF NOT EXISTS ioc_feeds (
    name            TEXT PRIMARY KEY,
    digest          TEXT NOT NULL DEFAULT '',   -- sha256 of the ingested bytes
    signed          BOOLEAN NOT NULL DEFAULT false,
    indicator_count INTEGER NOT NULL DEFAULT 0,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
