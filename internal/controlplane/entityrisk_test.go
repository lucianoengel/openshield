package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/controlplane"
	"github.com/lucianoengel/openshield/internal/gateway"
	"github.com/lucianoengel/openshield/internal/pseudonym"
	"github.com/lucianoengel/openshield/internal/xdr"
)

// TestEntityRiskIsCrossDomainAndRecencyWeighted: the aggregation itself.
//
// Mutation: drop the recency weight → the old alert scores the same as the recent one → FAILS.
// Mutation: sum instead of max → many low alerts outrank one critical → the max assertion FAILS.
func TestEntityRiskIsCrossDomainAndRecencyWeighted(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	now := time.Now().UTC()
	const window = time.Hour

	recent := pseudonym.Of("agent-risk-recent")
	old := pseudonym.Of("agent-risk-old")
	noisy := pseudonym.Of("agent-risk-noisy")

	// Same severity, different age.
	recordAlert(t, srv, "hips", recent, controlplane.SeverityCritical, now.Add(-2*time.Minute))
	recordAlert(t, srv, "hips", old, controlplane.SeverityCritical, now.Add(-55*time.Minute))
	// Many LOW alerts across domains: volume must not beat one critical.
	for i := 0; i < 8; i++ {
		recordAlert(t, srv, []string{"dlp", "nips", "ueba"}[i%3], noisy, controlplane.SeverityLow,
			now.Add(-time.Duration(i+1)*time.Minute))
	}

	scores, err := srv.EntityRisk(ctx, window, now)
	if err != nil {
		t.Fatal(err)
	}
	byAlias := map[string]float64{}
	for _, e := range scores {
		for _, a := range e.Aliases {
			byAlias[a] = e.Score
		}
	}
	if byAlias[recent] <= byAlias[old] {
		t.Errorf("a 2-minute-old critical scored %.3f and a 55-minute-old one %.3f — recency must weigh, "+
			"or one old alert pins an asset at high risk forever", byAlias[recent], byAlias[old])
	}
	if byAlias[noisy] >= byAlias[recent] {
		t.Errorf("8 low alerts scored %.3f vs one critical at %.3f — risk must be the WORST thing known "+
			"about an asset, not a function of alert volume", byAlias[noisy], byAlias[recent])
	}
	if byAlias[recent] < 0.8 {
		t.Errorf("a fresh critical scored only %.3f", byAlias[recent])
	}
}

// TestEntityRiskReachesEveryAlias is the cross-domain payoff: an ENDPOINT detection (device-keyed) must
// raise the risk a NETWORK consumer (user-keyed) applies, over REAL pub/sub.
//
// Mutation: publish only the first alias → the user-keyed consumer never sees it → FAILS.
func TestEntityRiskReachesEveryAlias(t *testing.T) {
	pool := requireDB(t)
	url := embeddedNATS(t)
	srv := controlplane.New(pool)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx, url) }()
	time.Sleep(150 * time.Millisecond)

	device := pseudonym.Of("agent-xdr7")
	const user = "xdr7-user@example.test"
	graph := xdr.NewStore(pool)
	if _, err := graph.Link(ctx, xdr.KindDevice, device, xdr.KindUser, user); err != nil {
		t.Fatal(err)
	}

	// SEC-1: risk updates must be SIGNED or the gateway would apply forged risk, so the publisher needs a
	// key and the subscriber the matching public one — the same pairing production uses.
	riskPub, riskPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetRiskSigner(riskPriv)

	// A consumer exactly like the access proxy: a RiskStore fed by the real subscriber over real NATS.
	store := gateway.NewRiskStore()
	conn, cerr := nats.Connect(url)
	if cerr != nil {
		t.Fatal(cerr)
	}
	defer conn.Close()
	if _, err := gateway.NewRiskSubscriber(store, riskPub).Subscribe(conn); err != nil {
		t.Fatal(err)
	}

	// An ENDPOINT (HIPS) detection on the DEVICE.
	now := time.Now().UTC()
	recordAlert(t, srv, "hips", device, controlplane.SeverityCritical, now.Add(-time.Minute))

	if _, err := srv.PublishEntityRisk(ctx, time.Hour, now); err != nil {
		t.Fatal(err)
	}
	// Both aliases receive it — the device⋈user link doing real work.
	waitFor(t, func() bool {
		d, okD := store.Get(device)
		u, okU := store.Get(user)
		return okD && okU && d > 0.5 && u > 0.5
	})
	u, _ := store.Get(user)
	t.Logf("a HIPS detection on the device raised the USER-keyed risk the access proxy sees to %.3f", u)
}

// TestPublishedRiskNeverLowersAnExistingSignal: turning cross-domain aggregation on must not make a subject
// look safer than the behavioural signal already says.
//
// Mutation: plain overwrite in RiskStore.Set → the lower value wins → FAILS.
func TestPublishedRiskNeverLowersAnExistingSignal(t *testing.T) {
	store := gateway.NewRiskStore()
	store.Set("sub_x", 0.9)
	store.Set("sub_x", 0.2)
	if got, _ := store.Get("sub_x"); got != 0.9 {
		t.Fatalf("risk = %.2f after a lower publication, want 0.90 — a new source must not be able to make "+
			"a subject look safer than another already says it is", got)
	}
	store.Set("sub_x", 0.95)
	if got, _ := store.Get("sub_x"); got != 0.95 {
		t.Errorf("risk = %.2f after a HIGHER publication, want 0.95", got)
	}
}
