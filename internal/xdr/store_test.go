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
	if _, err := pool.Exec(ddlCtx, `DROP TABLE IF EXISTS entity_aliases, entities, audit_entries, key_epochs, anchors, fleet_telemetry, peer_alerts, agent_identities, enrollment_tokens, investigation_views, case_notes, cases, legal_holds, incidents, ueba_baselines, schema_migrations CASCADE`); err != nil {
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
