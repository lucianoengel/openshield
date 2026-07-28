//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE FEED FORMAT IS NAMED, NEVER SNIFFED (SOAR-5, OPENSHIELD_TI_FEED_FORMAT).
//
// Public threat feeds come as CSV; the native format is one indicator per line. A parser that GUESSED
// between them would be convenient and would fail in the worst available way: a CSV misread as native
// does not error, it silently yields the wrong indicators — or none — and the platform then reports a
// clean fleet with an empty threat list. Detection that finds nothing is indistinguishable from an
// estate with nothing to find (D31), so the guess is not a usability trade-off, it is the failure mode.
//
// The setting is what makes it a declaration. These scenarios drive the real `ingest-feed` subcommand
// against a real database, because the format is read from the DYNAMIC configuration — the subcommand
// deliberately reads it from the store rather than its own environment, so that a re-ingest an hour
// later parses the same file the same way.

// csvFeed is a public-feed-shaped list: `kind,indicator` with the extra columns real feeds carry.
const csvFeed = `# kind,indicator,first_seen,notes
domain,evil.example,2026-01-01,tracked
ip,203.0.113.9,2026-01-02,scanner
`

// nativeFeed is the same two indicators in the native format.
const nativeFeed = "domain evil.example\nip 203.0.113.9\n"

// ingestedIndicators counts what a feed put in the store.
func ingestedIndicators(t *testing.T, stack *Stack, feed string) int {
	t.Helper()
	pool := openPool(t, stack.DSN)
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM ioc_indicators WHERE feed = $1`, feed).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestACsvFeedIsParsedAsCsvWhenDeclared.
func TestACsvFeedIsParsedAsCsvWhenDeclared(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	setDynamic(t, stack, "OPENSHIELD_TI_FEED_FORMAT", "csv")

	path := filepath.Join(t.TempDir(), "public.csv")
	if err := os.WriteFile(path, []byte(csvFeed), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCapture(t, "openshield-server", []string{"OPENSHIELD_DSN=" + stack.DSN},
		"ingest-feed", "public", path)
	if err != nil {
		t.Fatalf("ingesting a CSV feed declared as csv: %v\n%s", err, out)
	}
	if n := ingestedIndicators(t, stack, "public"); n != 2 {
		t.Errorf("a declared-CSV feed produced %d indicators, want 2 — the extra columns real public "+
			"feeds carry (a date, a note) must be ignored rather than rejected, or the format is "+
			"unusable against the feeds it exists for\n%s", n, out)
	}
}

// TestTheSameBytesUnderTheWrongFormatDoNotSilentlyHalfLoad is the claim proper.
//
// The same file, declared as the OTHER format, must not quietly produce a plausible-looking result. Two
// outcomes are acceptable and one is not: refusing it is ideal, and producing indicators that differ
// from the correct parse is at least detectable — what must never happen is the same count as a correct
// parse, because then no operator, and no test, can tell the two apart.
func TestTheSameBytesUnderTheWrongFormatDoNotSilentlyHalfLoad(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	setDynamic(t, stack, "OPENSHIELD_TI_FEED_FORMAT", "native") // the WRONG declaration for this file

	path := filepath.Join(t.TempDir(), "public.csv")
	if err := os.WriteFile(path, []byte(csvFeed), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCapture(t, "openshield-server", []string{"OPENSHIELD_DSN=" + stack.DSN},
		"ingest-feed", "misdeclared", path)

	// Refusal is the good outcome and is not required — but if it was accepted, the result must be
	// visibly different from a correct parse.
	if err == nil {
		if n := ingestedIndicators(t, stack, "misdeclared"); n == 2 {
			t.Errorf("CSV bytes declared as NATIVE produced the same 2 indicators a correct parse does — "+
				"so the declaration did nothing and the format is being inferred from content after all. "+
				"A feed that parses either way is a feed nobody can be sure of\n%s", out)
		}
	}
	t.Logf("CSV-as-native: err=%v stored=%d", err, ingestedIndicators(t, stack, "misdeclared"))
}

// TestReIngestingAFeedReplacesItsIndicators.
//
// A feed is a SNAPSHOT, not an append. An indicator that has been taken down — or was a false positive
// somebody withdrew — has to disappear on the next ingest, or the store accumulates every indicator the
// feed has ever carried and the operator can never retract one. That is the difference between a threat
// list and a memory of every threat list.
func TestReIngestingAFeedReplacesItsIndicators(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	setDynamic(t, stack, "OPENSHIELD_TI_FEED_FORMAT", "native")

	dir := t.TempDir()
	path := filepath.Join(dir, "feed.txt")
	ingest := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := runCapture(t, "openshield-server", []string{"OPENSHIELD_DSN=" + stack.DSN},
			"ingest-feed", "rolling", path); err != nil {
			t.Fatalf("ingesting: %v\n%s", err, out)
		}
	}

	ingest(nativeFeed) // two indicators
	if n := ingestedIndicators(t, stack, "rolling"); n != 2 {
		t.Fatalf("the first ingest stored %d indicators, want 2", n)
	}

	// The feed publisher WITHDRAWS one.
	ingest("domain evil.example\n")
	if n := ingestedIndicators(t, stack, "rolling"); n != 1 {
		t.Errorf("after a re-ingest that dropped an indicator the store holds %d, want 1. A feed is a "+
			"SNAPSHOT: appending means a taken-down indicator is flagged forever and a withdrawn false "+
			"positive can never be withdrawn", n)
	}

	pool := openPool(t, stack.DSN)
	var stale int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM ioc_indicators WHERE feed='rolling' AND value='203.0.113.9'`).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Errorf("the withdrawn indicator is still stored (%d rows)", stale)
	}
}

// THE DEDUPE LEDGER IS PRUNED TO THE OPERATOR'S RETENTION (SIEM-12, D333).
//
// The prune always ran, on a cutoff hardcoded to 24 hours — and then recorded a compliance event whose
// policy string was the literal `OPENSHIELD_NOTIFY_DEDUPE_RETENTION=24h`. So an operator who set that
// variable got their value ignored AND a retention record naming their setting while asserting a value
// they did not choose. A compliance record citing a knob nobody read is worse than one that omits it:
// it is evidence of a policy that was never applied.
func TestTheDedupeLedgerIsPrunedToTheConfiguredRetention(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	pool := openPool(t, stack.DSN)

	// Two ids: one old enough to fall outside a short retention, one fresh.
	if _, err := pool.Exec(Ctx(t),
		`INSERT INTO notify_dedupe (id, emitted_at) VALUES ('stale-id', now() - interval '10 minutes'),
		                                                  ('fresh-id', now())`); err != nil {
		t.Fatal(err)
	}

	setDynamic(t, stack, "OPENSHIELD_NOTIFY_DEDUPE_RETENTION", "1m")
	setDynamic(t, stack, "OPENSHIELD_RETENTION_INTERVAL", "1s")
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("openshield-server", 90*time.Second)

	remaining := func(id string) int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM notify_dedupe WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	Eventually(t, 90*time.Second, "the stale dedupe id to be pruned at the CONFIGURED retention", func() bool {
		return remaining("stale-id") == 0
	})
	// A 10-minute-old id survives a 24h cutoff and not a 1m one, so its removal is what proves the
	// operator's value was used rather than the constant that used to be hardcoded here.
	if n := remaining("fresh-id"); n != 1 {
		t.Errorf("a dedupe id emitted just now was pruned under a 1m retention (%d rows) — pruning inside "+
			"the dedupe window lets a duplicate page", n)
	}

	// AND THE COMPLIANCE RECORD SAYS WHAT ACTUALLY HAPPENED.
	var policy string
	if err := pool.QueryRow(Ctx(t),
		`SELECT policy FROM retention_events WHERE target='notify_dedupe' ORDER BY id DESC LIMIT 1`).
		Scan(&policy); err != nil {
		t.Fatal(err)
	}
	if !contains(policy, "1m") {
		t.Errorf("the retention event records policy %q while the operator configured 1m. A compliance "+
			"record that names a setting and asserts a value nobody applied is evidence of a policy that "+
			"never ran", policy)
	}
}
