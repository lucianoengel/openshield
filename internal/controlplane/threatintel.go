package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/lucianoengel/openshield/internal/nips"
)

// The server-side IOC store (SOAR-5).
//
// ONE MATCHER, TWO CONSUMERS. This package does NOT re-implement indicator matching. It persists what
// `nips` parsed and materializes the same `*nips.Feed` back, so the inline gateway engine and the
// analytical enrichment path share the parent-suffix domain rule (evil.com matches c2.evil.com but not
// notevil.com), the CIDR containment, and the minimum-length URI guard. A second implementation would
// eventually drift — and the drift would be between what gets BLOCKED and what gets REPORTED, which is
// the worst possible pair to disagree.
//
// (Matching in SQL was the alternative. Suffix matching and CIDR containment are both expressible in
// Postgres, but that IS a second implementation of the semantics. Feeds are small; loading one is cheap.)

// IngestFeed verifies, parses and stores a threat-intel feed under a name.
//
// Verification happens inside `nips.VerifyAndParse`, BEFORE the parser — a feed that fails is refused as
// a whole and nothing here runs. The write is one transaction that DELETEs the feed's existing rows and
// inserts the new set, so the store always reflects the snapshot the publisher currently asserts.
//
// Returns the number of indicators stored.
func (s *Server) IngestFeed(ctx context.Context, name string, data, sig []byte,
	pub ed25519.PublicKey, format nips.Format) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("threat intel: a feed needs a name — provenance is what makes an indicator actionable")
	}
	feed, err := nips.VerifyAndParse(data, sig, pub, format)
	if err != nil {
		return 0, fmt.Errorf("threat intel: feed %q refused: %w", name, err)
	}
	indicators := feed.Indicators()
	digest := sha256.Sum256(data)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// REPLACE, not append. See the snapshot argument in migration 033.
	if _, err := tx.Exec(ctx, `DELETE FROM ioc_indicators WHERE feed = $1`, name); err != nil {
		return 0, err
	}
	for _, in := range indicators {
		if _, err := tx.Exec(ctx,
			`INSERT INTO ioc_indicators (kind, value, feed) VALUES ($1,$2,$3)
			 ON CONFLICT (kind, value, feed) DO NOTHING`, in.Kind, in.Value, name); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO ioc_feeds (name, digest, signed, indicator_count, ingested_at)
		 VALUES ($1,$2,$3,$4, now())
		 ON CONFLICT (name) DO UPDATE SET digest = EXCLUDED.digest, signed = EXCLUDED.signed,
		     indicator_count = EXCLUDED.indicator_count, ingested_at = EXCLUDED.ingested_at`,
		name, hex.EncodeToString(digest[:]), len(pub) != 0, len(indicators)); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(indicators), nil
}

// FeedFromStore materializes every stored indicator into the matcher the inline engine uses.
//
// An empty store yields an empty feed, which matches nothing — so a deployment that has ingested no
// threat intel behaves exactly as it did before this existed, rather than failing.
func (s *Server) FeedFromStore(ctx context.Context) (*nips.Feed, error) {
	rows, err := s.pool.Query(ctx, `SELECT kind, value FROM ioc_indicators`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var indicators []nips.Indicator
	for rows.Next() {
		var in nips.Indicator
		if err := rows.Scan(&in.Kind, &in.Value); err != nil {
			return nil, err
		}
		indicators = append(indicators, in)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// BuildFeed re-validates: the store is not a trusted source just because it is ours.
	return nips.BuildFeed(indicators)
}

// FeedProvenance is what an analyst needs to answer "which feed, and which version of it, said this".
type FeedProvenance struct {
	Name           string    `json:"name"`
	Digest         string    `json:"digest"`
	Signed         bool      `json:"signed"`
	IndicatorCount int       `json:"indicator_count"`
	IngestedAt     time.Time `json:"ingested_at"`
}

// IngestedFeeds lists what has been ingested, newest first.
func (s *Server) IngestedFeeds(ctx context.Context) ([]FeedProvenance, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, digest, signed, indicator_count, ingested_at FROM ioc_feeds ORDER BY ingested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedProvenance
	for rows.Next() {
		var p FeedProvenance
		if err := rows.Scan(&p.Name, &p.Digest, &p.Signed, &p.IndicatorCount, &p.IngestedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// feedForIndicator names which feed asserted a matched indicator, so the annotation an analyst reads
// says WHO claims it. A value present in several feeds reports them all — corroboration is information.
func (s *Server) feedForIndicator(ctx context.Context, kind, value string) []string {
	rows, err := s.pool.Query(ctx,
		`SELECT feed FROM ioc_indicators WHERE kind=$1 AND value=$2 ORDER BY feed`, kind, value)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var feeds []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return feeds
		}
		feeds = append(feeds, f)
	}
	return feeds
}
