package gateway_test

import (
	"net/url"
	"testing"

	"github.com/lucianoengel/openshield/internal/gateway"
)

// Add/Resolve routes a known host; an uncatalogued host is not found (the caller
// refuses it — never an open relay, D88).
func TestCatalogResolve(t *testing.T) {
	c := gateway.NewCatalog()
	u, _ := url.Parse("http://payroll.internal:8080")
	c.Add("payroll", u)

	if _, ok := c.Resolve("payroll"); !ok {
		t.Error("a catalogued service was not resolved")
	}
	if _, ok := c.Resolve("unknown"); ok {
		t.Error("an uncatalogued host resolved — the catalog must be an allow-list")
	}
}

func TestParseCatalog(t *testing.T) {
	c, err := gateway.ParseCatalog("payroll=http://payroll.internal:8080, wiki=http://wiki.internal")
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 {
		t.Fatalf("Len = %d, want 2", c.Len())
	}
	for _, h := range []string{"payroll", "wiki"} {
		if _, ok := c.Resolve(h); !ok {
			t.Errorf("service %q did not resolve", h)
		}
	}

	// A malformed entry (no '=') and an unparseable/host-less URL each error, not
	// silently skipped.
	for _, bad := range []string{"payroll", "svc=", "svc=:::not a url", "svc=/no-host"} {
		if _, err := gateway.ParseCatalog(bad); err == nil {
			t.Errorf("ParseCatalog(%q) did not error", bad)
		}
	}
}
