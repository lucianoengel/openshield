//go:build integration

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CONSOLE-5 AGAINST THE SHIPPED SERVER.
//
// The package tests prove that the wrapper records before it serves and refuses when it cannot. They
// cannot prove the two things that actually failed here:
//
//  1. That the mounted read surface goes through the wrapper at all. Before this change every one of
//     these routes was mounted, tested, reachable, and recorded nothing — an audit is only real if the
//     binary an operator connects to applies it, and a package test that calls the wrapper directly is
//     satisfied by a wrapper nobody mounted. This project has now found unwired code in D313, D415,
//     D417, D418 and CONSOLE-1's own /report/response; a route with no wrapper looks exactly like a
//     route that works.
//  2. That the retention purge runs. Its ONLY writer is cmd/openshield-server's retention loop.

// recordedViews reads the view audit straight from the database. The privacy officer's /views route is
// the operator-facing reader (D470, proven by TestOnlyThePrivacyOfficerReleasesALegalHold); here the
// claim is about what the SERVER WROTE, so reading the table directly keeps a broken reader from being
// able to hide a broken writer.
func recordedViews(t *testing.T, pool *pgxpool.Pool, viewer string) map[string]string {
	t.Helper()
	rows, err := pool.Query(Ctx(t),
		`SELECT route, query FROM investigation_views WHERE viewer = $1`, viewer)
	if err != nil {
		t.Fatalf("reading the view audit: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var route, query string
		if err := rows.Scan(&route, &query); err != nil {
			t.Fatal(err)
		}
		out[route] = query
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheConsolesPrimaryReadsAreRecordedByTheShippedServer.
//
// docs/threat-model.md bounds the malicious insider holding an operator role with "who LOOKED is
// recorded". Every route below returns, or narrows to, what the platform holds about a subject, an
// entity or an endpoint's activity — and every one of them recorded NOTHING before CONSOLE-5. An
// analyst could search the fleet aggregate for a named host, read the ingested third-party log store and
// page the entity graph, leaving an empty accountability table behind.
//
// Mutation: revert the mount to `opRead := s.OperatorReadHandler()` in enroll_http.go → every audited
// route records nothing and this FAILS. (Verified.)
func TestTheConsolesPrimaryReadsAreRecordedByTheShippedServer(t *testing.T) {
	p := newPKI(t)
	stack, _, base := mtlsServer(t, p)
	pool := openPool(t, stack.DSN)

	const cn = "console-reader"
	const principal = "cert:" + cn
	analyst := p.operator(t, "analyst", cn)
	operatorRoleCmd(t, stack, "set", principal, "analyst")

	// The console's primary reads. Each is served with a filter, so the recorded row can be checked for
	// carrying WHAT was read and not only that a read happened.
	audited := []string{
		"/alerts?limit=5",
		"/search?subject=subject-console-5",
		"/events?agent=host-console-5",
		"/logs?vendor=acme",
		"/incidents?window=1h",
		"/incidents/recurrences?id=1",
		"/entities?window=1h",
		"/searches/run?name=nonexistent",
	}
	for _, path := range audited {
		// The STATUS IS NOT THE CLAIM. A saved search that does not exist answers 404 and an incident
		// recurrence for a missing incident answers 404 too — and the view is still recorded, which is
		// correct: an attempted read of an investigation is worth recording whether or not it found
		// anything. Only an authorization refusal would invalidate the case below.
		if code, body := do(t, analyst, http.MethodGet, base+path, nil); code == http.StatusUnauthorized ||
			code == http.StatusForbidden {
			t.Fatalf("GET %s was refused (%d %s) — this case is about recording, so the analyst has to "+
				"reach the route first", path, code, body)
		}
	}
	// The platform's own liveness report is EXEMPT, with the reason written down in viewAuditExempt. It
	// is asserted here as the other half: without it, every assertion above is satisfied by a server
	// that records every request indiscriminately, which is not a per-route decision.
	if code, body := do(t, analyst, http.MethodGet, base+"/health", nil); code != http.StatusOK {
		t.Fatalf("GET /health: %d %s", code, body)
	}

	got := recordedViews(t, pool, principal)
	for _, want := range []string{"/alerts", "/search", "/events", "/logs", "/incidents",
		"/incidents/recurrences", "/entities", "/searches/run"} {
		if _, ok := got[want]; !ok {
			t.Errorf("the shipped server recorded no view for %s. It is one of the console's primary "+
				"reads, and 'who LOOKED is recorded' is what bounds the malicious-operator insider in "+
				"the threat model — recorded: %v", want, got)
		}
	}
	if q := got["/search"]; q != "subject=subject-console-5" {
		t.Errorf("the recorded query for /search is %q — a record that does not say what was searched "+
			"for cannot distinguish a dashboard refresh from a search for one named person", q)
	}
	if _, exempt := got["/health"]; exempt {
		t.Error("the liveness report was recorded as an investigation view — the exemption table is not " +
			"being consulted, so the per-route decision is not in force")
	}

	// AND THE SUBJECT SEARCH IS JOINABLE TO THE SUBJECT. /search?subject= lifts the subject into the
	// column the DSAR counts on; without it "who looked at me" finds nothing.
	var n int
	if err := pool.QueryRow(Ctx(t),
		`SELECT count(*) FROM investigation_views WHERE subject_filter = 'subject-console-5'`).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("a search that NAMED a subject was recorded without that subject, so the subject's own " +
			"access report cannot find it")
	}
}

// TestTheViewAuditIsPurgedToTheConfiguredRetention.
//
// Migration 007 shipped `investigation_views` with no TTL, no purge and no DSAR path while storing raw,
// non-pseudonymised operator identities. It was the one subject-adjacent store in this product that grew
// forever — and a console makes it the largest table in the database.
//
// The purge's only writer is cmd/openshield-server's leader-only retention loop, so a package test
// cannot prove it runs. This drives the real binary with a one-minute window through the real config
// table, exactly as the sibling notify-dedupe case does.
//
// Mutation: remove the PurgeViewsOlderThan block from the retention loop in main.go → the stale row
// survives and this FAILS. (Verified.)
func TestTheViewAuditIsPurgedToTheConfiguredRetention(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	pool := openPool(t, stack.DSN)

	// One view old enough to fall outside a one-minute window, one just recorded.
	if _, err := pool.Exec(Ctx(t),
		`INSERT INTO investigation_views (viewer, subject_filter, event_id, route, query, viewed_at)
		 VALUES ('cert:stale-reader','s1','', '/events','', now() - interval '10 minutes'),
		        ('cert:fresh-reader','s2','', '/events','', now())`); err != nil {
		t.Fatal(err)
	}

	setDynamic(t, stack, "OPENSHIELD_VIEW_AUDIT_RETENTION", "1m")
	setDynamic(t, stack, "OPENSHIELD_RETENTION_INTERVAL", "1s")
	srv := Start(t, "openshield-server", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
	})
	srv.WaitForOutput("openshield-server", 90*time.Second)

	remaining := func(viewer string) int {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM investigation_views WHERE viewer = $1`, viewer).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	Eventually(t, 90*time.Second, "the stale view record to be purged at the CONFIGURED retention", func() bool {
		return remaining("cert:stale-reader") == 0
	})
	// A ten-minute-old row survives the 8760h default and not a 1m one, so its removal is what proves
	// the operator's value was read rather than a constant.
	if n := remaining("cert:fresh-reader"); n != 1 {
		t.Errorf("a view recorded just now was purged under a 1m retention (%d rows) — an accountability "+
			"record a purge can reach early leaves a disputed read with nothing to be checked against", n)
	}

	// AND THE ERASURE IS PROVABLE TO THE SAME AUDITOR AS EVERY OTHER PURGE. Without the compliance
	// event, "we delete the record of who looked after a year" is a claim with no evidence behind it —
	// which is the gap SIEM-10 exists to close for every other purge in this product.
	var rows int64
	var policy string
	if err := pool.QueryRow(Ctx(t),
		`SELECT rows_affected, policy FROM retention_events WHERE target='investigation_views'
		 ORDER BY id DESC LIMIT 1`).Scan(&rows, &policy); err != nil {
		t.Fatalf("the view-audit purge recorded no compliance event: %v", err)
	}
	if !contains(policy, "1m") {
		t.Errorf("the retention event records policy %q while the operator configured 1m — a compliance "+
			"record naming a setting while asserting a value nobody applied is evidence of a policy that "+
			"never ran (D333)", policy)
	}
}
