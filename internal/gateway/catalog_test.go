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
