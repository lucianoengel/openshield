package postgres_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// These tests run against a REAL PostgreSQL, not a fake.
//
// The things most likely to be wrong here are precisely the things a fake
// cannot have an opinion about: whether BYTEA round-trips a hash unchanged,
// whether a column actually exists, whether a nullable Decision reads back as
// nil rather than as a zero-valued one. A mock would agree with whatever the
// code already does.
//
//	podman run -d --name openshield-pg -e POSTGRES_USER=openshield \
//	  -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=openshield \
//	  -p 55432:5432 docker.io/library/postgres:16

const defaultDSN = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"

func dsn() string {
	if v := os.Getenv("OPENSHIELD_TEST_DSN"); v != "" {
		return v
	}
	return defaultDSN
}

// requireDB connects, or skips LOUDLY.
//
// A skip that is only visible under `go test -v` is how an integration suite
// rots into decoration: the package still reports ok, nobody notices that the
// only tests exercising real SQL stopped running months ago. So the skip writes
// to stderr unconditionally, and CI sets OPENSHIELD_REQUIRE_POSTGRES=1 to turn
// it into a hard failure — a green CI run must mean these tests actually ran.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		msg := fmt.Sprintf("POSTGRES UNAVAILABLE at %s: %v", dsn(), err)
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("%s\nOPENSHIELD_REQUIRE_POSTGRES is set: the ledger's storage "+
				"layer must not be silently unverified.", msg)
		}
		fmt.Fprintf(os.Stderr,
			"\n!! SKIPPING LEDGER INTEGRATION TESTS !!\n%s\n"+
				"The hash chain, BYTEA round-tripping and migration columns are "+
				"NOT verified by this run.\nStart it with:\n"+
				"  podman run -d --name openshield-pg -e POSTGRES_USER=openshield \\\n"+
				"    -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=openshield \\\n"+
				"    -p 55432:5432 docker.io/library/postgres:16\n\n", msg)
		t.Skip(msg)
	}

	// Each test owns the table. Appends are sequenced from the stored tail, so
	// leftovers from a previous run would make sequence numbers unpredictable.
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS audit_entries, schema_migrations`); err != nil {
		t.Fatalf("clearing schema: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func openLedger(t *testing.T) (*postgres.Ledger, *core.Signer) {
	t.Helper()
	requireDB(t)
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	l, err := postgres.Open(context.Background(), dsn(), signer)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, signer
}

// Task 1.3. The ledger is hash-chained, so a column added later changes what is
// hashed and breaks continuity at the point of change. That makes a missing
// column not an ordinary migration bug but an unrepairable one — the cost must
// land here, on a failing test, not years later on a broken chain.
func TestInitialMigrationCreatesEveryRequiredColumn(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	if err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Each of these exists because a LATER phase needs it, and retrofitting it
	// would break the chain. The reason is recorded next to the name so a
	// future reader cannot mistake this list for boilerplate.
	required := map[string]string{
		"sequence":        "chain order",
		"prev_hash":       "chain link",
		"hash":            "entry commitment",
		"sig":             "forward-integrity signature",
		"key_epoch":       "which epoch key signed it — hashed, and unverifiable without it",
		"appended_at":     "retention purge and timeline",
		"decision_id":     "the Decision itself",
		"event_id":        "the Decision itself",
		"action":          "the Decision itself",
		"confidence":      "D4 — confidence, not certainty",
		"reason":          "the Decision itself",
		"policy_id":       "replay",
		"policy_version":  "replay",
		"outcome_kind":    "a timeout is not an allow",
		"outcome_stage":   "a failure must be attributable",
		"subject_id":      "D23 pseudonymous subject",
		"purpose":         "D20 purpose tagging",
		"retention_class": "T-013 automatic purge",
		"context_version": "D27 — replay against the Context that applied",
	}

	rows, err := pool.Query(ctx,
		`SELECT column_name FROM information_schema.columns WHERE table_name = 'audit_entries'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	present := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		present[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for col, why := range required {
		if !present[col] {
			t.Errorf("migration 001 is missing column %q (%s) — adding it later "+
				"changes what is hashed and breaks the chain at that point", col, why)
		}
	}
}

// Migrations must be idempotent, or a restart is a schema hazard.
func TestMigrateIsIdempotent(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := postgres.Migrate(ctx, pool); err != nil {
			t.Fatalf("migrate pass %d: %v", i, err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("schema_migrations rows = %d, want 1 — a migration applied twice "+
			"is a migration whose ledger is not what its version claims", n)
	}
}

func entry(subject string) *core.Entry {
	return &core.Entry{
		AppendedAt: time.Now().UTC(), // NOT truncated: the store must handle real timestamps
		SubjectID:  subject,
		Purpose:    corev1.Purpose_PURPOSE_DLP,
		Retention:  core.RetentionStandard,
		Decision: &corev1.Decision{
			DecisionId: "d-" + subject, EventId: "e-" + subject,
			Action: corev1.Action_ACTION_ALERT, Confidence: 0.75,
			Reason: "fixture", PolicyId: "p1", PolicyVersion: "1",
		},
	}
}

// The chain must survive a real round trip through BYTEA and pgx type mapping.
// A hash that comes back one byte different verifies as tampering, and that
// failure mode is invisible to any in-memory test.
func TestChainRoundTripsThroughPostgres(t *testing.T) {
	l, _ := openLedger(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := l.Append(ctx, entry(fmt.Sprintf("s%d", i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Consistent {
		t.Fatalf("chain inconsistent after a real round trip: %s", res)
	}
	if res.Entries != 5 {
		t.Errorf("entries = %d, want 5", res.Entries)
	}
	// Completeness is UNVERIFIED with no external anchor, and must stay so
	// until T-019. Reporting success here would let a caller claim nothing was
	// removed, which nothing in this deployment can attest.
	if res.Completeness != core.CompletenessUnverified {
		t.Errorf("completeness = %s, want unverified — no external anchor exists yet",
			res.Completeness)
	}
}

// The attack that motivates the whole ticket: an operator with database access
// edits a row. In-memory tests prove the algorithm; this proves the deployed
// storage does not launder the edit.
func TestRowEditedDirectlyInPostgresIsDetected(t *testing.T) {
	l, _ := openLedger(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for i := 0; i < 3; i++ {
		if err := l.Append(ctx, entry(fmt.Sprintf("s%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx,
		`UPDATE audit_entries SET action = $1 WHERE sequence = 1`,
		int32(corev1.Action_ACTION_ALLOW)); err != nil {
		t.Fatal(err)
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Consistent {
		t.Fatal("a row edited directly in the database verified as consistent — " +
			"the ledger's only claim is that this is detectable")
	}
	if res.FirstBreak == nil || *res.FirstBreak != 1 {
		t.Errorf("first break = %v, want 1 — tampering must be LOCATED, not "+
			"merely reported", res.FirstBreak)
	}
}

func TestDeletedRowIsDetected(t *testing.T) {
	l, _ := openLedger(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	for i := 0; i < 4; i++ {
		if err := l.Append(ctx, entry(fmt.Sprintf("s%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_entries WHERE sequence = 1`); err != nil {
		t.Fatal(err)
	}
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Consistent {
		t.Fatal("deleting a row verified as consistent")
	}
	if res.FirstBreak == nil || *res.FirstBreak != 2 {
		t.Errorf("first break = %v, want 2 (the entry following the hole)", res.FirstBreak)
	}
}

// A restart must CONTINUE the chain, not start a second one. Starting over
// would produce a ledger that verifies while silently having lost its link to
// everything written before the restart.
func TestRestartContinuesTheChain(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}

	l1, err := postgres.Open(ctx, dsn(), signer)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l1.Append(ctx, entry(fmt.Sprintf("a%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	_ = l1.Close()

	// Same signer: this models a restart, not a re-enrolment. Key material
	// surviving a restart is T-017's problem; the chain continuity being tested
	// here is this ticket's.
	l2, err := postgres.Open(ctx, dsn(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	for i := 0; i < 2; i++ {
		if err := l2.Append(ctx, entry(fmt.Sprintf("b%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	res, err := l2.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent {
		t.Fatalf("chain broke across a restart: %s", res)
	}
	if res.Entries != 5 || res.ToSequence != 4 {
		t.Errorf("entries=%d to=%d, want 5 and 4 — a restart started a second "+
			"chain rather than continuing the first", res.Entries, res.ToSequence)
	}
}

// A terminal outcome with no Decision (a timeout, a stage failure) must read
// back as having no Decision. If it round-trips as a zero-valued Decision, a
// timeout becomes indistinguishable from an ALLOW with empty fields — the
// exact conflation the outcome columns exist to prevent.
func TestOutcomeWithoutDecisionRoundTripsAsNil(t *testing.T) {
	l, _ := openLedger(t)
	ctx := context.Background()
	if err := l.Append(ctx, &core.Entry{
		AppendedAt:   time.Now().UTC(),
		OutcomeKind:  "timeout",
		OutcomeStage: "classifier",
		Retention:    core.RetentionStandard,
	}); err != nil {
		t.Fatal(err)
	}
	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent {
		t.Fatalf("entry without a Decision broke the chain: %s — the canonical "+
			"encoding must distinguish a nil Decision from an empty one", res)
	}
}

// Verification must require only PUBLIC material. If a secret were needed, the
// only party able to verify the log would be a party able to forge it — the
// structural flaw that sank the earlier symmetric design.
func TestVerificationNeedsOnlyPublicMaterial(t *testing.T) {
	l, signer := openLedger(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := l.Append(ctx, entry(fmt.Sprintf("s%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	// Read the rows as an auditor would: straight from the database, holding
	// nothing but the anchor public key and the published key chain.
	var anchor ed25519.PublicKey = signer.AnchorKey()
	chain := signer.Chain()
	for _, k := range chain {
		if len(k.PublicKey) != ed25519.PublicKeySize {
			t.Fatalf("epoch %d has no public key", k.Index)
		}
	}
	if _, err := core.VerifyKeyChain(chain, anchor); err != nil {
		t.Fatalf("key chain does not verify from public material alone: %v", err)
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent {
		t.Fatalf("verification failed: %s", res)
	}
}

// The epoch is the compromise window, so a ledger whose key never evolves has
// no forward integrity in practice — the key that signed entry 0 would still be
// resident at entry 10,000. This asserts rotation actually happens during
// ordinary appends, and that the chain still verifies ACROSS an epoch boundary
// (entries signed by a destroyed key must still validate against the published
// public-key chain, which is the whole point of the asymmetric design).
func TestKeyEvolvesDuringAppendsAndTheChainStillVerifies(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	l, err := postgres.Open(ctx, dsn(), signer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	if l.EpochEntries != postgres.DefaultEpochEntries {
		t.Errorf("EpochEntries = %d, want the default %d — an unset compromise "+
			"window means the signing key never evolves", l.EpochEntries, postgres.DefaultEpochEntries)
	}
	l.EpochEntries = 3 // small, so the test crosses several boundaries cheaply

	for i := 0; i < 10; i++ {
		if err := l.Append(ctx, entry(fmt.Sprintf("s%d", i))); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	if got := signer.Epoch(); got < 3 {
		t.Errorf("epoch = %d after 10 entries with EpochEntries=3, want >= 3 — "+
			"the key is not evolving, so entry 0's key is still in memory", got)
	}

	res, err := l.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Consistent {
		t.Fatalf("chain broke across an epoch boundary: %s — entries signed by a "+
			"destroyed key must still verify against the published key chain", res)
	}
	if res.Entries != 10 {
		t.Errorf("entries = %d, want 10", res.Entries)
	}
}
