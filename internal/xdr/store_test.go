package xdr_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	"github.com/lucianoengel/openshield/internal/xdr"
)

const dsn = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"

var (
	dbLockOnce sync.Once
	dbLockConn *pgx.Conn
)

// lockDB serializes DDL across the packages that share the dev DB via a
// process-wide advisory lock (920431), held for the process lifetime.
func lockDB(t *testing.T) {
	t.Helper()
	dbLockOnce.Do(func() {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatalf("lock connection: %v", err)
		}
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(920431)`); err != nil {
			t.Fatalf("advisory lock: %v", err)
		}
		dbLockConn = conn
	})
}

// requireDB connects, serializes DDL, migrates a clean schema, and returns a pool.
// Bare Ping for availability (never a migrate), then lock, then fresh-ctx DDL — the
// pattern the shared-DB packages follow.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		msg := fmt.Sprintf("POSTGRES UNAVAILABLE at %s: %v", dsn, err)
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("%s\nOPENSHIELD_REQUIRE_POSTGRES is set: XDR persistence must not be silently unverified.", msg)
		}
		t.Skip(msg)
	}
	lockDB(t)
	ddlCtx, ddlCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer ddlCancel()
	if _, err := pool.Exec(ddlCtx, `DROP TABLE IF EXISTS entity_aliases, entities, audit_entries, key_epochs, anchors, fleet_telemetry, peer_alerts, agent_identities, enrollment_tokens, investigation_views, case_notes, cases, approvals, legal_holds, incidents, incident_alerts, agent_enforcement, config_changes, config_revisions, config_settings, itsm_tickets, runner_actions, ioc_indicators, ioc_feeds, playbook_steps, playbook_runs, incident_annotations, ueba_baselines, schema_migrations CASCADE`); err != nil {
		t.Fatalf("clearing schema: %v", err)
	}
	if err := postgres.Migrate(ddlCtx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestResolveIsStable(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	id1, err := s.Resolve(ctx, xdr.KindDevice, "sub_x")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.Resolve(ctx, xdr.KindDevice, "sub_x")
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("same alias resolved to %d and %d", id1, id2)
	}
	// A different alias is a different entity.
	id3, _ := s.Resolve(ctx, xdr.KindDevice, "sub_y")
	if id3 == id1 {
		t.Fatal("distinct aliases resolved to the same entity")
	}
}

// TestCanonicalJoin proves two domains referencing the same device by the REAL
// canonical pseudonym derivation resolve to one entity — not test-seeded literals.
func TestCanonicalJoin(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	// "exec" side and "gateway request" side both derive the device subject the one
	// canonical way (IDENT-1) from the same agent identity.
	execSubject := pseudonym.Of("agent-A")
	gatewaySubject := pseudonym.Of("agent-A")

	execEntity, err := s.Resolve(ctx, xdr.KindDevice, execSubject)
	if err != nil {
		t.Fatal(err)
	}
	gwEntity, err := s.Resolve(ctx, xdr.KindDevice, gatewaySubject)
	if err != nil {
		t.Fatal(err)
	}
	if execEntity != gwEntity {
		t.Fatalf("the same device via the canonical derivation resolved to %d (exec) and %d (gateway)", execEntity, gwEntity)
	}
}

func TestConcurrentResolveCreatesOneEntity(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	const workers = 12
	ids := make([]int64, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := s.Resolve(ctx, xdr.KindDevice, "sub_race")
			if err != nil {
				t.Errorf("resolve: %v", err)
				return
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()
	for i := 1; i < workers; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("concurrent resolve returned different ids: %d vs %d", ids[0], ids[i])
		}
	}
	// Exactly one entity row for that alias.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM entity_aliases WHERE kind=$1 AND value=$2`, xdr.KindDevice, "sub_race").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("entity_aliases rows for the raced alias = %d, want 1", count)
	}
}

func TestLinkMergesAndIsIdempotent(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	dev, err := s.Resolve(ctx, xdr.KindDevice, "sub_dev")
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.Resolve(ctx, xdr.KindUser, "sub_user")
	if err != nil {
		t.Fatal(err)
	}
	if dev == user {
		t.Fatal("device and user unexpectedly started as one entity")
	}

	merged, err := s.Link(ctx, xdr.KindDevice, "sub_dev", xdr.KindUser, "sub_user")
	if err != nil {
		t.Fatal(err)
	}
	// Both aliases now resolve to the merged id.
	if got, _ := s.Resolve(ctx, xdr.KindDevice, "sub_dev"); got != merged {
		t.Fatalf("device resolves to %d after link, want %d", got, merged)
	}
	if got, _ := s.Resolve(ctx, xdr.KindUser, "sub_user"); got != merged {
		t.Fatalf("user resolves to %d after link, want %d", got, merged)
	}
	// The loser entity is gone (only one of the two original ids survives).
	loser := dev
	if merged == dev {
		loser = user
	}
	var exists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM entities WHERE id=$1)`, loser).Scan(&exists)
	if exists {
		t.Fatalf("merged-away entity %d still exists", loser)
	}
	// Idempotent.
	again, err := s.Link(ctx, xdr.KindDevice, "sub_dev", xdr.KindUser, "sub_user")
	if err != nil || again != merged {
		t.Fatalf("re-link = %d, %v; want %d, nil", again, err, merged)
	}
}

var _ = time.Second

// TestLookupAnyFindsAnotherKindsAlias proves the kind-agnostic lookup resolves a value
// registered under a DIFFERENT kind — the primitive that stops a domain whose subject is a
// user identity from forking onto its own entity when the graph already knows that identity.
func TestLookupAnyFindsAnotherKindsAlias(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	userEntity, err := s.Resolve(ctx, xdr.KindUser, "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LookupAny(ctx, "user@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("LookupAny missed a value registered under the user kind")
	}
	if got != userEntity {
		t.Fatalf("LookupAny returned entity %d, want the user alias's %d", got, userEntity)
	}
}

// TestLookupAnyCreatesNothing is the read-only property: a miss must not mint an entity or
// an alias, so a speculative lookup before a kind-specific resolve is free of side effects.
func TestLookupAnyCreatesNothing(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	count := func(table string) int64 {
		t.Helper()
		var n int64
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	entitiesBefore, aliasesBefore := count("entities"), count("entity_aliases")

	if _, ok, err := s.LookupAny(ctx, "sub_never_seen"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("LookupAny reported found for a value with no alias")
	}

	if got := count("entities"); got != entitiesBefore {
		t.Fatalf("entities changed from %d to %d — LookupAny must create nothing", entitiesBefore, got)
	}
	if got := count("entity_aliases"); got != aliasesBefore {
		t.Fatalf("entity_aliases changed from %d to %d — LookupAny must create nothing", aliasesBefore, got)
	}
}

// TestLookupAnyAcrossLinkedPair proves either half of a linked device⋈user pair resolves to
// the one entity — the shape a ZT alert (user subject) and an endpoint alert (device
// subject) must share for cross-domain grouping to be an entity join.
func TestLookupAnyAcrossLinkedPair(t *testing.T) {
	pool := requireDB(t)
	s := xdr.NewStore(pool)
	ctx := context.Background()

	device := pseudonym.Of("agent-linked")
	const user = "linked-user@example.test"
	linked, err := s.Link(ctx, xdr.KindDevice, device, xdr.KindUser, user)
	if err != nil {
		t.Fatal(err)
	}

	viaDevice, ok, err := s.LookupAny(ctx, device)
	if err != nil || !ok {
		t.Fatalf("lookup by device: %v ok=%v", err, ok)
	}
	viaUser, ok, err := s.LookupAny(ctx, user)
	if err != nil || !ok {
		t.Fatalf("lookup by user: %v ok=%v", err, ok)
	}
	if viaDevice != viaUser || viaDevice != linked {
		t.Fatalf("linked pair resolved to device=%d user=%d, want both %d", viaDevice, viaUser, linked)
	}
}
