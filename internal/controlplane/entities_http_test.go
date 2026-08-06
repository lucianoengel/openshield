package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// CONSOLE-9: the entity surface.
//
// The device⋈user graph (D203) and per-entity risk (D255) were both live and both DATABASE-ONLY, and
// `xdr.Store` had no reader at all — every operation answered "what is the id for THIS name" and none
// could answer "what does the platform know". The coalescing the lane exists to perform was invisible to
// the operators it was performed for.

// freshGraph returns the pool as well as the store, because requireDB DROPS and re-migrates: calling it
// a second time mid-test silently wipes what the test just seeded. The first version of the non-vacuity
// assertion below did exactly that and reported an empty graph — the fixture is destructive by design, so
// it must be called once.
func freshGraph(t *testing.T) (*controlplane.Server, *xdr.Store, *pgxpool.Pool) {
	t.Helper()
	pool := requireDB(t)
	execSQL(t, pool, `DELETE FROM unified_alerts`)
	execSQL(t, pool, `DELETE FROM entity_aliases`)
	execSQL(t, pool, `DELETE FROM entities`)
	return controlplane.New(pool), xdr.NewStore(pool), pool
}

// TestAnAssetIsReturnedWithEveryNameItIsKnownBy.
//
// The pivot the console is built around: from one alert, "this device is also known as what, and to
// whom?" Returning only the alias searched for would answer nothing — the entity exists precisely
// because two names are one asset.
//
// Mutation: return only the seed alias (drop the self-join in EntityFor) → FAILS.
func TestAnAssetIsReturnedWithEveryNameItIsKnownBy(t *testing.T) {
	srv, store, _ := freshGraph(t)
	ctx := context.Background()

	if _, err := store.Link(ctx, xdr.KindDevice, "sub_dev_a", xdr.KindUser, "sub_usr_a"); err != nil {
		t.Fatal(err)
	}

	got, ok, err := srv.EntityFor(ctx, "sub_dev_a", time.Hour, time.Now())
	if err != nil || !ok {
		t.Fatalf("EntityFor(device) = ok %v, err %v", ok, err)
	}
	if len(got.Aliases) != 2 {
		t.Fatalf("entity carries %d alias(es), want both names: %+v — an asset that resolves to only "+
			"the name you already had is not a coalesced identity", len(got.Aliases), got.Aliases)
	}
	// AND FROM THE OTHER END. The pivot has to work from whichever name the operator happens to hold.
	fromUser, ok, err := srv.EntityFor(ctx, "sub_usr_a", time.Hour, time.Now())
	if err != nil || !ok {
		t.Fatalf("EntityFor(user) = ok %v, err %v", ok, err)
	}
	if fromUser.ID != got.ID {
		t.Errorf("the device and the user resolved to different entities (%d vs %d) — they are linked",
			got.ID, fromUser.ID)
	}
}

// TestAnEntityWithNoRecentAlertsHasNoRiskRatherThanZero.
//
// THE HOUSE RULE, applied again: a zero a reader could mistake for a measurement must be nullable. Risk
// 0.0 reads as "we assessed this asset and it is fine"; the truth is "nothing has been seen recently",
// and those are different answers to the question an operator brings to this page.
//
// Mutation: make Risk a plain float64 → FAILS (it serializes as 0 for a quiet asset).
func TestAnEntityWithNoRecentAlertsHasNoRiskRatherThanZero(t *testing.T) {
	srv, store, pool := freshGraph(t)
	ctx := context.Background()
	if _, err := store.Link(ctx, xdr.KindDevice, "sub_quiet", xdr.KindUser, "sub_quiet_u"); err != nil {
		t.Fatal(err)
	}

	got, err := srv.EntitiesWithRisk(ctx, time.Hour, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("graph holds %d entities, want 1", len(got))
	}
	if got[0].Risk != nil {
		t.Errorf("risk = %v for an asset with no alerts in the window — zero reads as an assessment, "+
			"and nothing has assessed this asset", *got[0].Risk)
	}
	body, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"risk"`) {
		t.Errorf("an absent risk is present on the wire: %s", body)
	}

	// THE POSITIVE HALF, and it is not decoration. Everything above asserts an ABSENCE, so it would
	// pass just as well against a risk join that never returns anything — the vacuous shape of every
	// "the field is correctly empty" test. A noisy asset must actually carry a score.
	execSQL(t, pool,
		`INSERT INTO unified_alerts (entity_id, domain, severity, dedup_key, detected_at)
		 VALUES ($1,'dlp','critical','entity-risk-positive', now())`, got[0].ID)

	loud, err := srv.EntitiesWithRisk(ctx, time.Hour, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(loud) != 1 || loud[0].Risk == nil {
		t.Fatalf("an asset with a CRITICAL alert in the window carries no risk (%+v) — the assertions "+
			"above would then hold for a join that returns nothing at all", loud)
	}
	if *loud[0].Risk <= 0 {
		t.Errorf("risk = %v for a critical alert just now, want a positive score", *loud[0].Risk)
	}
}

// TestReadingTheGraphDoesNotGrowIt.
//
// Resolve creates on first sight, which is right for ingest and wrong for a lookup. A read that invented
// an entity would make the graph grow by being looked at, and every typo in a console search would leave
// a permanent empty node.
//
// Mutation: implement EntityFor with Resolve → FAILS.
func TestReadingTheGraphDoesNotGrowIt(t *testing.T) {
	srv, store, pool := freshGraph(t)
	ctx := context.Background()
	if _, err := store.Link(ctx, xdr.KindDevice, "sub_real", xdr.KindUser, "sub_real_u"); err != nil {
		t.Fatal(err)
	}
	before := countRows(t, pool, `SELECT count(*) FROM entities`)

	if _, ok, err := srv.EntityFor(ctx, "sub_typo_nobody_has", time.Hour, time.Now()); err != nil || ok {
		t.Fatalf("a value naming nothing resolved: ok %v, err %v", ok, err)
	}
	if after := countRows(t, pool, `SELECT count(*) FROM entities`); after != before {
		t.Errorf("entities went from %d to %d by being SEARCHED FOR — every mistyped console search "+
			"would leave a permanent empty node", before, after)
	}
}

// TestAnUnknownValueIsNotAnEmptyEntity — "no entity is known by that name" and "this entity has nothing
// recorded" are different answers, and a console rendering both as an empty page would let a typo look
// like a clean asset.
func TestAnUnknownValueIsNotAnEmptyEntity(t *testing.T) {
	srv, _, _ := freshGraph(t)
	ca := newOneCA(t)

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/entities?value=nobody", "entity-reader", "analyst"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /entities?value=nobody = %d, want 404 — an empty answer would make a typo look "+
			"like an asset with a clean record", rec.Code)
	}
}

// TestThePageCountsEntitiesNotRows.
//
// A limit applied to the flat alias join returns a PARTIAL entity, and half a coalesced identity is
// worse than none because it looks complete — an operator would see a device that had never been linked
// to a user.
//
// Mutation: LIMIT the joined result instead of the entity subquery → FAILS.
func TestThePageCountsEntitiesNotRows(t *testing.T) {
	srv, store, _ := freshGraph(t)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if _, err := store.Link(ctx, xdr.KindDevice, "sub_dev_"+n, xdr.KindUser, "sub_usr_"+n); err != nil {
			t.Fatal(err)
		}
	}

	got, err := srv.EntitiesWithRisk(ctx, time.Hour, time.Now(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("limit=2 returned %d entities", len(got))
	}
	for _, e := range got {
		if len(e.Aliases) != 2 {
			t.Errorf("entity %d came back with %d alias(es) under a page limit — the limit counted "+
				"ROWS, so this asset looks like it was never linked to a user", e.ID, len(e.Aliases))
		}
	}
}

// TestTheEntityRouteIsAnalystTierAndRefusedWithoutACredential.
func TestTheEntityRouteIsAnalystTierAndRefusedWithoutACredential(t *testing.T) {
	srv, _, _ := freshGraph(t)
	ca := newOneCA(t)

	rec := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/entities", "entity-reader", "analyst"))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /entities as analyst = %d %q", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if body := rec.Body.String(); strings.Contains(body, "null") {
		t.Errorf("an empty graph serialized as null: %s", body)
	}

	anon := httptest.NewRecorder()
	controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
		ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/entities", nil))
	if anon.Code != http.StatusUnauthorized && anon.Code != http.StatusForbidden {
		t.Errorf("GET /entities with NO credential = %d", anon.Code)
	}
}

// TestAMalformedWindowIsRefusedRatherThanDefaulted (SEC-8): a caller who asked for 24h and silently got
// 1h would read "no risk" as "nothing happened today".
func TestAMalformedWindowIsRefusedRatherThanDefaulted(t *testing.T) {
	srv, _, _ := freshGraph(t)
	ca := newOneCA(t)

	for _, q := range []string{"?window=lastweek", "?window=-1h", "?window=0"} {
		rec := httptest.NewRecorder()
		controlplane.RequireTierForTestHandler(srv, controlplane.RoleAnalyst, srv.OperatorReadHandler()).
			ServeHTTP(rec, certReq(t, ca, http.MethodGet, "/entities"+q, "entity-reader", "analyst"))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET /entities%s = %d, want 400", q, rec.Code)
		}
	}
}
