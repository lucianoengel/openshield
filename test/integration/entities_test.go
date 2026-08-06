//go:build integration

package integration

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/xdr"
)

// CONSOLE-9 AGAINST THE SHIPPED BINARY.
//
// The device⋈user graph is populated by the GATEWAY (XDR-1-WIRE) and by the control plane's own ingest,
// and was READ BY NOTHING — `xdr.Store` had no reader at all.
//
// WHAT THIS PROVES AND WHAT IT DOES NOT, stated plainly. It seeds through the real store rather than
// through a dual-credential proxy request: the WRITER is not in question here — `TestGatewayLinksDeviceAndUser`
// drives it at package level and `cmd/openshield-gateway:424` wires `SetEntityGraph`, so it is a producer
// with a caller. What was in question is whether anything can READ what that path writes, over the surface
// an operator actually reaches, and that is what runs here against the shipped server.

type entityBody struct {
	ID      int64    `json:"id"`
	Risk    *float64 `json:"risk"`
	Aliases []struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"aliases"`
}

func TestTheEntityGraphIsReadableFromTheOperatorAPI(t *testing.T) {
	p := newPKI(t)
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)

	addr := "127.0.0.1:" + freePort(t)
	Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 60*time.Second)

	analyst := p.operator(t, "analyst", "entity-watcher")

	// AN EMPTY GRAPH IS AN EMPTY LIST, not a null and not an error. A console that had to distinguish
	// "nothing linked yet" from "the read failed" by checking for null would get it wrong once.
	var initial []entityBody
	getOperatorJSON(t, analyst, "https://"+addr+"/entities", &initial)
	if len(initial) != 0 {
		t.Fatalf("a fresh deployment already holds %d entities: %+v", len(initial), initial)
	}

	// Seed through the REAL resolver the ingest path uses, then read it back over HTTP. The gateway's
	// own link is exercised by TestPostureChainRealPathEndToEnd and the XDR-6 scenarios; what is new
	// here is that anything can READ what they wrote.
	pool := openPool(t, stack.DSN)
	linkEntity(t, pool, "sub_dev_console9", "sub_usr_console9")

	var listed []entityBody
	Eventually(t, 30*time.Second, "the linked asset to appear on the operator surface", func() bool {
		listed = nil
		getOperatorJSON(t, analyst, "https://"+addr+"/entities", &listed)
		return len(listed) == 1
	})
	if n := len(listed[0].Aliases); n != 2 {
		t.Fatalf("the asset lists %d alias(es), want the device AND the user: %+v — one name is not a "+
			"coalesced identity, and the graph exists to say these are one asset", n, listed[0].Aliases)
	}
	// RISK IS ABSENT, not zero: no alert concerns this asset. Zero would say "assessed and fine".
	if listed[0].Risk != nil {
		t.Errorf("risk = %v for an asset with no alerts", *listed[0].Risk)
	}

	// THE PIVOT, from either end. An operator holding either name reaches the same asset.
	for _, seed := range []string{"sub_dev_console9", "sub_usr_console9"} {
		var one entityBody
		getOperatorJSON(t, analyst, "https://"+addr+"/entities?value="+seed, &one)
		if one.ID != listed[0].ID {
			t.Errorf("pivoting from %q reached entity %d, want %d", seed, one.ID, listed[0].ID)
		}
		if len(one.Aliases) != 2 {
			t.Errorf("pivoting from %q returned %d alias(es), want both", seed, len(one.Aliases))
		}
	}

	// AN UNKNOWN NAME IS A 404, and the graph does not grow by being searched. A read that created
	// would leave a permanent empty node for every typo an operator makes.
	resp, err := analyst.Get("https://" + addr + "/entities?value=sub_nobody_typed_this")
	if err != nil {
		t.Fatalf("GET /entities?value=unknown: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown value returned %d, want 404 — an empty answer makes a typo look like an "+
			"asset with a clean record", resp.StatusCode)
	}
	var after []entityBody
	getOperatorJSON(t, analyst, "https://"+addr+"/entities", &after)
	if len(after) != len(listed) {
		t.Errorf("the graph grew from %d to %d entities by being SEARCHED", len(listed), len(after))
	}

	// AND IT IS BEHIND THE OPERATOR GATE.
	anon := p.bearerClient(t)
	if r, aerr := anon.Get("https://" + addr + "/entities"); aerr != nil {
		if !strings.Contains(aerr.Error(), "certificate required") {
			t.Errorf("anonymous GET /entities failed unexpectedly: %v", aerr)
		}
	} else {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized && r.StatusCode != http.StatusForbidden {
			t.Errorf("an unauthenticated caller read the entity graph: %d", r.StatusCode)
		}
	}
}

// linkEntity writes one device⋈user link through the REAL store the gateway uses.
//
// Not through the gateway itself: its linking path needs a dual-credential request (device certificate
// plus a distinct OIDC user), which TestGatewayLinksDeviceAndUser already drives at package level, and
// cmd/openshield-gateway:424 wires SetEntityGraph so the producer is not in question. What was in
// question — and what this scenario is for — is whether anything can READ what that path writes.
func linkEntity(t *testing.T, pool *pgxpool.Pool, device, user string) {
	t.Helper()
	if _, err := xdr.NewStore(pool).Link(Ctx(t), xdr.KindDevice, device, xdr.KindUser, user); err != nil {
		t.Fatalf("linking %s to %s: %v", device, user, err)
	}
}
