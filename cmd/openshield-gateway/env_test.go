package main

import (
	"net"
	"testing"

	"github.com/lucianoengel/openshield/internal/dnsredirect"
)

// The gateway's env parsers decide WHAT IT INTERCEPTS, and every one of them was at 0%.
//
// They share a discipline that is easy to lose in a refactor: a misconfigured value falls back to the
// DEFAULT, never to "nothing". The distinction matters because "nothing" is silent — a typo in the port
// list would leave the inline plane running, logging happily, and intercepting no traffic at all, which
// looks identical to a quiet network.

func TestEnvPortsFallsBackToTheDefaultRatherThanToNothing(t *testing.T) {
	def := []int{443, 8443}
	const key = "OPENSHIELD_TEST_PORTS"

	for _, tc := range []struct {
		name string
		set  bool
		val  string
		want []int
	}{
		{"unset", false, "", def},
		{"empty", true, "", def},
		{"only whitespace", true, "   ", def},
		{"a single port", true, "8080", []int{8080}},
		{"several", true, "80,443,8080", []int{80, 443, 8080}},
		{"whitespace around each", true, " 80 , 443 ", []int{80, 443}},

		// A partly-bad list keeps what parsed. Dropping the whole list because one entry was fat-fingered
		// would silently stop intercepting ports the operator did get right.
		{"one bad token among good", true, "80,nope,443", []int{80, 443}},
		{"zero is not a port", true, "0,443", []int{443}},
		{"negative is not a port", true, "-1,443", []int{443}},

		// ENTIRELY unusable: fall back to the default, NOT to an empty list.
		{"all tokens bad", true, "nope,also-nope", def},
		{"all non-positive", true, "0,-5", def},
		{"commas only", true, ",,,", def},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(key, tc.val)
			}
			got := envPorts(key, def)
			if len(got) == 0 {
				t.Fatalf("envPorts(%q) returned an EMPTY list — the gateway would intercept nothing and "+
					"say nothing about it", tc.val)
			}
			if !sameInts(got, tc.want) {
				t.Fatalf("envPorts(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// The fwmark is written as hex in the documentation and the nft rules (0x1d5), so base-0 parsing is not a
// nicety — decimal-only parsing would read "0x1d5" as invalid, fall back to the default, and produce a
// redirect whose exemption mark does not match the one the resolver sets. That is the loop the mark exists
// to break, and it would come back as a DNS timeout rather than anything naming the mark.
func TestEnvMarkAcceptsHexAsWellAsDecimal(t *testing.T) {
	const key = "OPENSHIELD_TEST_MARK"
	const def = 0x1d5

	for _, tc := range []struct {
		name string
		set  bool
		val  string
		want int
	}{
		{"unset", false, "", def},
		{"empty", true, "", def},
		{"hex, as the docs write it", true, "0x1d5", 0x1d5},
		{"hex, different value", true, "0xff", 255},
		{"decimal", true, "469", 469},
		{"octal", true, "0o17", 15},
		{"whitespace around", true, "  0x1d5  ", 0x1d5},
		{"not a number", true, "mark", def},
		{"trailing junk", true, "0x1d5oops", def},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv(key, tc.val)
			}
			if got := envMark(key, def); got != tc.want {
				t.Fatalf("envMark(%q) = %#x, want %#x", tc.val, got, tc.want)
			}
		})
	}
}

// The second return value is the whole point: an unrecognised scope must be REPORTED, not quietly treated
// as "local". Silently narrowing the scope an operator asked for is how a gateway ends up not covering the
// traffic it was deployed to cover.
func TestDNSRedirectScopeReportsAnUnrecognisedValue(t *testing.T) {
	for _, tc := range []struct {
		val   string
		want  dnsredirect.Scope
		valid bool
	}{
		{"1", dnsredirect.ScopeLocal, true},
		{"local", dnsredirect.ScopeLocal, true},
		{"LOCAL", dnsredirect.ScopeLocal, true},
		{"  Local  ", dnsredirect.ScopeLocal, true},
		{"forwarded", dnsredirect.ScopeForwarded, true},
		{"FORWARDED", dnsredirect.ScopeForwarded, true},
		{"both", dnsredirect.ScopeBoth, true},
		{"", dnsredirect.ScopeLocal, false},
		{"2", dnsredirect.ScopeLocal, false},
		{"all", dnsredirect.ScopeLocal, false},
		{"loc", dnsredirect.ScopeLocal, false},
		// NOT a prefix match for "forwarded". The rejected value still comes back as ScopeLocal, the
		// safest of the three, so a caller that ignores the ok flag narrows rather than widens.
		{"forward", dnsredirect.ScopeLocal, false},
	} {
		t.Run("value="+tc.val, func(t *testing.T) {
			got, ok := dnsRedirectScope(tc.val)
			if ok != tc.valid {
				t.Fatalf("dnsRedirectScope(%q) valid = %v, want %v", tc.val, ok, tc.valid)
			}
			// Checked in BOTH cases. The returned scope on a rejection is not "don't care": a caller that
			// logs and continues gets this value, and it must be the narrow one.
			if got != tc.want {
				t.Fatalf("dnsRedirectScope(%q) = %v, want %v", tc.val, got, tc.want)
			}
		})
	}
}

// listenPort exists so a ":0" ephemeral listen reports the port the kernel actually chose. Reading the
// configured string instead would report 0, and 0 is what gets written into the redirect rule.
func TestListenPortPrefersTheBoundSocket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bound net.Addr
		addr  string
		want  int
	}{
		{"udp bound wins", &net.UDPAddr{Port: 34567}, "127.0.0.1:0", 34567},
		{"tcp bound wins", &net.TCPAddr{Port: 34568}, "127.0.0.1:0", 34568},
		{"udp port 0 falls back to the configured address", &net.UDPAddr{Port: 0}, "127.0.0.1:5353", 5353},
		{"tcp port 0 falls back", &net.TCPAddr{Port: 0}, "127.0.0.1:5353", 5353},
		{"nil bound falls back", nil, "0.0.0.0:8053", 8053},
		{"an address type it does not know falls back", &net.UnixAddr{Name: "/tmp/x"}, ":9053", 9053},
		{"unparseable address and no bound port", nil, "not-an-address", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenPort(tc.bound, tc.addr); got != tc.want {
				t.Fatalf("listenPort(%v, %q) = %d, want %d", tc.bound, tc.addr, got, tc.want)
			}
		})
	}
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
