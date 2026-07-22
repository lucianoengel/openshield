package gateway_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/gateway/identity"
	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/store/postgres"
	"github.com/lucianoengel/openshield/internal/xdr"
)

const gatewayDSN = "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable"

var (
	gwLockOnce sync.Once
	gwLockConn *pgx.Conn // package-level so the held advisory lock is not GC-closed for the process
)

// gwLockDB holds the process-wide advisory lock (same key as postgres/controlplane) for the WHOLE test
// binary. The other DB-mutating packages DROP+recreate shared tables (including entity_aliases) while
// holding this lock for their entire run; releasing it after migrate would let one of them drop the
// graph out from under an in-flight gateway test. So the gateway holds it for the process too.
func gwLockDB(t *testing.T) {
	t.Helper()
	gwLockOnce.Do(func() {
		conn, err := pgx.Connect(context.Background(), gatewayDSN)
		if err != nil {
			t.Fatalf("lock connection: %v", err)
		}
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(920431)`); err != nil {
			t.Fatalf("acquiring advisory lock: %v", err)
		}
		gwLockConn = conn
	})
}

// requireGatewayDB connects (or skips loudly), holds the shared advisory lock for the process, and
// ensures the schema exists.
func requireGatewayDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, gatewayDSN)
	if err == nil {
		err = pool.Ping(ctx)
	}
	if err != nil {
		if pool != nil {
			pool.Close()
		}
		msg := fmt.Sprintf("POSTGRES UNAVAILABLE at %s: %v", gatewayDSN, err)
		if os.Getenv("OPENSHIELD_REQUIRE_POSTGRES") != "" {
			t.Fatalf("%s\nOPENSHIELD_REQUIRE_POSTGRES is set.", msg)
		}
		t.Skip(msg)
	}
	gwLockDB(t) // held for the process, so cross-package DDL cannot drop the graph mid-test
	mctx, mcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer mcancel()
	if err := postgres.MigrateIfNeeded(mctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestGatewayLinksDeviceAndUser (XDR-1-WIRE, gateway producer): a dual-credential request (device cert
// + OIDC user) drives the access proxy to LINK the device and user aliases into one entity in the XDR
// graph — asynchronously and best-effort. Proven through the real ServeHTTP path with a real graph.
//
// Mutation: removing the linkDeviceUser call in ServeHTTP leaves the two aliases unlinked (or absent)
// → the "same entity id" assertion FAILS.
func TestGatewayLinksDeviceAndUser(t *testing.T) {
	pool := requireGatewayDB(t)

	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	verifier, err := identity.NewOIDCVerifier("https://issuer.example", "openshield-gateway", "groups",
		map[string]crypto.PublicKey{"k1": edPub})
	if err != nil {
		t.Fatal(err)
	}

	up, hit := accessUpstream(t)
	pol, err := policy.New(context.Background(), "oidc", "1", `package openshield
import rego.v1
decision := {"action":"ALLOW","reason":"finance","confidence":0.9} if { input.context.role == "finance" }
decision := {"action":"BLOCK","reason":"deny","confidence":0.9} if { input.context.role != "finance" }`)
	if err != nil {
		t.Fatal(err)
	}
	gw := gateway.New(&fakeWorker{}, pol, &recLedger{}, nil, time.Second)
	cat := gateway.NewCatalog()
	upURL, _ := url.Parse(up.URL)
	cat.Add("127.0.0.1", upURL)
	ap := gateway.NewAccessProxy(gw, cat, 0, nil)
	ap.SetOIDCVerifier(verifier)
	ap.SetEntityGraph(xdr.NewStore(pool)) // the wiring under test

	ca := newAccessCA(t)
	addr := serveAccessTLS(t, ap, ca)
	// Unique per run: the entity graph persists across runs, so fixed ids would already be linked from
	// a prior run and mask a regression (removing the link would still "pass"). Fresh ids each run make
	// the gateway the SOLE creator of these aliases.
	stamp := time.Now().UnixNano()
	deviceCN := fmt.Sprintf("device-xdrlink-%d", stamp)
	userSub := fmt.Sprintf("user-xdrlink-%d@corp", stamp)
	client := accessClient(ca.clientCert(t, deviceCN, "device"), ca.pool)

	tok := mintJWT(t, "k1", edPriv, map[string]any{
		"iss": "https://issuer.example", "aud": "openshield-gateway", "sub": userSub,
		"groups": []string{"finance"}, "exp": time.Now().Add(time.Hour).Unix(), "nbf": time.Now().Add(-time.Minute).Unix()})
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !hit.Load() {
		t.Fatalf("authorized request = %d (hit %v), want 200 + upstream reached", resp.StatusCode, hit.Load())
	}

	// The link is async — wait for both aliases to resolve to the SAME entity.
	deviceSubject := pseudonym.Of(deviceCN)
	userSubject := pseudonym.Of(userSub)
	var devID, usrID int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		devID, _ = aliasID(pool, xdr.KindDevice, deviceSubject)
		usrID, _ = aliasID(pool, xdr.KindUser, userSubject)
		if devID != 0 && usrID != 0 && devID == usrID {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if devID == 0 || usrID == 0 {
		t.Fatalf("device (%d) or user (%d) alias missing — the gateway did not populate the graph", devID, usrID)
	}
	if devID != usrID {
		t.Fatalf("device entity %d != user entity %d — the dual-credential request did not LINK them", devID, usrID)
	}
}

func aliasID(pool *pgxpool.Pool, kind, value string) (int64, error) {
	var id int64
	err := pool.QueryRow(context.Background(),
		`SELECT entity_id FROM entity_aliases WHERE kind=$1 AND value=$2`, kind, value).Scan(&id)
	return id, err
}
