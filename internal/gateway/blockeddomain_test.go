package gateway_test

import (
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// TestBlockedDomain covers the DNS-sinkhole block accessor: a domain (and its subdomain) on the IOC
// feed is blocked, an unrelated one is not, and a gateway with no feed blocks nothing.
func TestBlockedDomain(t *testing.T) {
	g := gateway.New(&fakeWorker{}, deciding(0), &recLedger{}, nil, 0)
	if g.BlockedDomain("evil.com") {
		t.Fatal("no feed configured must block nothing")
	}
	g.SetThreatFeed(feedTo(t, "domain c2.evil.com\n"))
	if !g.BlockedDomain("c2.evil.com") {
		t.Error("a feed domain must be blocked")
	}
	if !g.BlockedDomain("host.c2.evil.com") {
		t.Error("a subdomain of a feed domain must be blocked")
	}
	if g.BlockedDomain("example.com") {
		t.Error("an unrelated domain must not be blocked")
	}
}
