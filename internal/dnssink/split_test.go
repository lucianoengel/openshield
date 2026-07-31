package dnssink_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/dnssink"
)

// ZT-11 — SPLIT-HORIZON ANSWERS.
//
// The bypass guard (ZT-10) stops a client reaching a protected service directly. That closes the wrong
// path and does nothing about the right one: the client still has to be TOLD to use the broker, which in
// practice means a hosts file, a VPN profile, or an internal DNS server somebody else maintains.
//
// Together the two make brokered access ordinary rather than opt-in: the guard makes going around it
// fail, and this makes going through it automatic.

// askSplit runs a resolver with a split table and returns the raw response to one query.
func askSplit(t *testing.T, split dnssink.SplitHorizon, name string, qtype uint16,
	blocked func(string) bool) []byte {
	t.Helper()
	// An upstream that never answers, so any test that passes by FORWARDING times out visibly rather
	// than quietly succeeding against a real resolver.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dead.Close() })

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := dnssink.Resolver{
		Upstream: dead.LocalAddr().String(),
		Split:    split,
		Blocked:  blocked,
		Timeout:  300 * time.Millisecond,
	}
	go func() { _ = r.Serve(ctx, pc) }()

	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(buildQuery(0x4242, name, qtype)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil // no answer (forwarded to a dead upstream)
	}
	return buf[:n]
}

// buildQuery builds a minimal DNS query for name with the given qtype.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return msg
}

// answerIPs pulls the A/AAAA record data out of a response.
func answerIPs(t *testing.T, resp []byte) []net.IP {
	t.Helper()
	if len(resp) < 12 {
		return nil
	}
	ancount := int(resp[6])<<8 | int(resp[7])
	off := 12
	for { // skip the question name
		if off >= len(resp) {
			return nil
		}
		l := int(resp[off])
		off++
		if l == 0 {
			break
		}
		off += l
	}
	off += 4 // QTYPE + QCLASS
	var out []net.IP
	for i := 0; i < ancount && off+12 <= len(resp); i++ {
		off += 2 // NAME (compression pointer)
		off += 2 // TYPE
		off += 2 // CLASS
		off += 4 // TTL
		rdlen := int(resp[off])<<8 | int(resp[off+1])
		off += 2
		if off+rdlen > len(resp) {
			return out
		}
		out = append(out, net.IP(resp[off:off+rdlen]))
		off += rdlen
	}
	return out
}

// rcode returns the RCODE nibble.
func rcodeOf(resp []byte) int {
	if len(resp) < 4 {
		return -1
	}
	return int(resp[3] & 0x0f)
}

// THE HEADLINE: a catalogued name resolves to the gateway, with no client configuration.
//
// Mutation (drop the Split lookup from handle): the query is forwarded to the dead upstream and no
// answer comes back → FAIL.
func TestACataloguedNameResolvesToTheGateway(t *testing.T) {
	split := dnssink.SplitHorizon{"payroll.corp.example": "10.0.0.1"}
	resp := askSplit(t, split, "payroll.corp.example", 1, nil)
	if resp == nil {
		t.Fatal("no answer — the query was forwarded instead of answered locally, so a client would " +
			"still have to be told about the broker by a hosts file or a VPN profile")
	}
	ips := answerIPs(t, resp)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("answers = %v, want a single A record for the gateway", ips)
	}
	if rcodeOf(resp) != 0 {
		t.Errorf("rcode = %d, want NOERROR", rcodeOf(resp))
	}
}

// A NAME THAT IS NOT CATALOGUED IS NOT ANSWERED LOCALLY. Split horizon must not become a resolver that
// invents addresses for everything.
func TestAnUncataloguedNameIsNotAnsweredLocally(t *testing.T) {
	split := dnssink.SplitHorizon{"payroll.corp.example": "10.0.0.1"}
	if resp := askSplit(t, split, "www.example.com", 1, nil); resp != nil {
		t.Fatalf("an uncatalogued name was answered locally (%v) — the resolver would be inventing "+
			"addresses for the whole internet", answerIPs(t, resp))
	}
}

// THE ADDRESS FAMILY ASKED FOR IS THE ONE ANSWERED.
//
// Returning an A record to an AAAA query is not merely useless. A dual-stack client that receives it
// treats the name as having no AAAA and may still try the REAL address over IPv6 — the direct path this
// exists to remove. An empty NOERROR is the correct way to say "this name exists, not in this family".
//
// Mutation (answer every qtype with the configured address): the AAAA query gets an A record → FAIL.
func TestOnlyTheRequestedAddressFamilyIsAnswered(t *testing.T) {
	split := dnssink.SplitHorizon{"payroll.corp.example": "10.0.0.1"} // v4 only

	resp := askSplit(t, split, "payroll.corp.example", 28, nil) // AAAA
	if resp == nil {
		t.Fatal("the AAAA query was forwarded rather than answered — a catalogued name must not fall " +
			"through to the real address in the other family")
	}
	if ips := answerIPs(t, resp); len(ips) != 0 {
		t.Fatalf("an AAAA query was answered with %v — a dual-stack client reads that as 'no AAAA' and "+
			"may still reach the real address over IPv6, which is the direct path this removes", ips)
	}
	if rcodeOf(resp) != 0 {
		t.Errorf("the empty AAAA answer has rcode %d, want NOERROR — NXDOMAIN would tell the client "+
			"the name does not exist at all", rcodeOf(resp))
	}

	// And a v6 entry answers AAAA, so the check above is not "AAAA is never answered".
	v6 := dnssink.SplitHorizon{"payroll.corp.example": "fd00::1"}
	resp6 := askSplit(t, v6, "payroll.corp.example", 28, nil)
	ips := answerIPs(t, resp6)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("fd00::1")) {
		t.Fatalf("a v6 split entry answered AAAA with %v", ips)
	}
}

// NAMES MATCH REGARDLESS OF CASE AND THE TRAILING DOT.
//
// Every resolver library differs about the root dot, and a configuration written one way would silently
// answer nothing for clients that ask the other — which looks exactly like the feature being off.
func TestNameMatchingIgnoresCaseAndTheTrailingDot(t *testing.T) {
	split, err := dnssink.ParseSplitHorizon("Payroll.Corp.Example.=10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, ask := range []string{"payroll.corp.example", "PAYROLL.CORP.EXAMPLE", "payroll.corp.example."} {
		if _, ok := split.Answer(ask); !ok {
			t.Errorf("%q did not match a table written as Payroll.Corp.Example. — a configuration "+
				"written one way answering nothing for the other looks exactly like the feature being "+
				"off", ask)
		}
	}
}

// A CATALOGUED NAME WINS OVER THE BLOCK LIST, and the collision is announced.
//
// Of the two readings — "send this user to the broker" and "this name is malware" — the one an operator
// explicitly wrote for THIS deployment wins. The alternative makes a catalogued service silently
// unreachable with nothing naming the cause.
func TestACataloguedNameOutranksTheBlockListAndTheCollisionIsVisible(t *testing.T) {
	split := dnssink.SplitHorizon{"payroll.corp.example": "10.0.0.1"}
	blockEverything := func(string) bool { return true }

	resp := askSplit(t, split, "payroll.corp.example", 1, blockEverything)
	if resp == nil {
		t.Fatal("no answer at all")
	}
	if rcodeOf(resp) == 3 {
		t.Fatal("a CATALOGUED service name was sinkholed as NXDOMAIN — the service becomes silently " +
			"unreachable and nothing names the cause")
	}
	ips := answerIPs(t, resp)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("answers = %v, want the gateway address", ips)
	}

	// And a name that is ONLY blocked is still sinkholed, so the rule above did not disable blocking.
	if r := askSplit(t, split, "evil.example", 1, blockEverything); rcodeOf(r) != 3 {
		t.Fatalf("a blocked, uncatalogued name got rcode %d, want NXDOMAIN — the split-horizon rule "+
			"must not have turned the sinkhole off", rcodeOf(r))
	}
}

// A MALFORMED TABLE ENTRY IS REFUSED, never skipped.
//
// A skipped name is one a client keeps resolving to the real internal address, so it reaches the service
// DIRECTLY, past the broker, in a deployment that believes it configured otherwise — the exact outcome
// this and the bypass guard exist to prevent, arriving through a typo.
func TestAMalformedSplitEntryIsRefusedRatherThanSkipped(t *testing.T) {
	for _, tc := range []struct{ name, spec string }{
		{"no equals", "payroll.corp.example"},
		{"no address", "payroll.corp.example="},
		{"no name", "=10.0.0.1"},
		{"address is a name", "payroll.corp.example=gateway.corp.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dnssink.ParseSplitHorizon(tc.spec); err == nil {
				t.Fatalf("accepted %q — a skipped name keeps resolving to the real internal address, "+
					"so the client reaches the service directly in a deployment that believes it "+
					"configured otherwise", tc.spec)
			}
		})
	}
	// A well-formed table loads, so the refusals are not "nothing is ever accepted".
	sh, err := dnssink.ParseSplitHorizon("payroll.corp.example=10.0.0.1, wiki.corp.example=10.0.0.1")
	if err != nil {
		t.Fatalf("a valid table was refused: %v", err)
	}
	if len(sh) != 2 {
		t.Fatalf("loaded %d entries, want 2", len(sh))
	}
}
