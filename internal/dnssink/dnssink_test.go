package dnssink

import (
	"context"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// buildQuery builds a minimal DNS A query for name with a fixed transaction id.
func buildQuery(id uint16, name string) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0} // RD=1, QDCOUNT=1
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)       // root label
	msg = append(msg, 0x00, 0x01) // QTYPE = A
	msg = append(msg, 0x00, 0x01) // QCLASS = IN
	return msg
}

// stubUpstream is a UDP server that records whether it was queried and replies a canned message.
type stubUpstream struct {
	pc      net.PacketConn
	queried atomic.Bool
	reply   []byte
}

func newStubUpstream(t *testing.T, reply []byte) *stubUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stubUpstream{pc: pc, reply: reply}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			s.queried.Store(true)
			// Echo the query's txn id into the canned reply so the client matches it.
			r := make([]byte, len(s.reply))
			copy(r, s.reply)
			if n >= 2 && len(r) >= 2 {
				r[0], r[1] = buf[0], buf[1]
			}
			pc.WriteTo(r, addr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return s
}

// runResolver starts a resolver on a high UDP port and returns its address.
func runResolver(t *testing.T, r Resolver) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.Serve(ctx, pc)
	return pc.LocalAddr()
}

// query sends q to addr and returns the response (within a short timeout).
func query(t *testing.T, addr net.Addr, q []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	return buf[:n]
}

func rcode(resp []byte) byte {
	if len(resp) < 4 {
		return 0xff
	}
	return resp[3] & 0x0f
}

// TestSinkholesBlockedDomain: a query for a blocked domain (and a subdomain) gets NXDOMAIN and the
// upstream is NOT queried.
//
// Mutation (Serve forwards instead of sinkholing): the upstream is queried / no NXDOMAIN → this test FAILs.
func TestSinkholesBlockedDomain(t *testing.T) {
	up := newStubUpstream(t, buildQuery(0, "x")) // any canned bytes; must NOT be used
	blocked := map[string]bool{"evil.com": true}
	r := Resolver{Upstream: up.pc.LocalAddr().String(), Blocked: func(n string) bool {
		// exact or parent-suffix match
		for d := n; d != ""; {
			if blocked[d] {
				return true
			}
			i := strings.IndexByte(d, '.')
			if i < 0 {
				break
			}
			d = d[i+1:]
		}
		return false
	}}
	addr := runResolver(t, r)

	for _, name := range []string{"evil.com", "c2.evil.com"} {
		resp := query(t, addr, buildQuery(0x1234, name))
		if rcode(resp) != 3 {
			t.Fatalf("%s: rcode = %d, want 3 (NXDOMAIN)", name, rcode(resp))
		}
		if resp[0] != 0x12 || resp[1] != 0x34 {
			t.Errorf("%s: response txn id not echoed", name)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if up.queried.Load() {
		t.Fatal("the upstream was queried for a sinkholed domain — a blocked domain must not be forwarded")
	}
}

// TestForwardsNormalQuery: a query for a non-blocked domain is forwarded and the upstream's response relayed.
func TestForwardsNormalQuery(t *testing.T) {
	canned := append(buildQuery(0, "good.com"), 0xde, 0xad) // distinctive trailing bytes to identify the relay
	up := newStubUpstream(t, canned)
	r := Resolver{Upstream: up.pc.LocalAddr().String(), Blocked: func(string) bool { return false }}
	addr := runResolver(t, r)

	resp := query(t, addr, buildQuery(0x5678, "good.com"))
	if !up.queried.Load() {
		t.Fatal("the upstream was not queried for a normal domain")
	}
	if len(resp) < 2 || resp[len(resp)-2] != 0xde || resp[len(resp)-1] != 0xad {
		t.Fatal("the client did not receive the upstream's relayed response")
	}
}

// TestMarkZeroForwardsPlainly: with Mark == 0 the upstream forward is the historical plain-dial path — a
// normal query is still relayed byte-for-byte (the loop-break machinery must not perturb the default).
func TestMarkZeroForwardsPlainly(t *testing.T) {
	canned := append(buildQuery(0, "good.com"), 0xbe, 0xef)
	up := newStubUpstream(t, canned)
	r := Resolver{Upstream: up.pc.LocalAddr().String(), Blocked: func(string) bool { return false }, Mark: 0}
	addr := runResolver(t, r)

	resp := query(t, addr, buildQuery(0x1234, "good.com"))
	if !up.queried.Load() {
		t.Fatal("Mark==0: the upstream was not queried")
	}
	if len(resp) < 2 || resp[len(resp)-2] != 0xbe || resp[len(resp)-1] != 0xef {
		t.Fatal("Mark==0: the client did not receive the relayed upstream response (plain path perturbed)")
	}
}

// TestMarkSelectsControlPath: on linux a non-zero Mark builds the SO_MARK dial Control (the loop-break).
// The actual setsockopt needs CAP_NET_ADMIN and is exercised by the gated VM test; here we assert only that
// the control path is selected on linux (and is inert off linux where the redirect does not exist).
func TestMarkSelectsControlPath(t *testing.T) {
	c := markControl(0x1d5)
	if runtime.GOOS == "linux" {
		if c == nil {
			t.Fatal("linux: Mark>0 must build a non-nil dial Control for SO_MARK")
		}
	} else if c != nil {
		t.Fatal("non-linux: markControl must be inert (nil)")
	}
}

// TestFailOpenOnUnparseable: a garbage datagram (not a valid query) is FORWARDED, not dropped/sinkholed.
//
// Mutation (drop instead of forward on a parse error): the upstream is never queried → this test FAILs.
func TestFailOpenOnUnparseable(t *testing.T) {
	up := newStubUpstream(t, []byte{0, 0, 0x80, 0}) // any reply
	// Blocked would sinkhole "evil.com", but the garbage never parses, so it must be forwarded regardless.
	r := Resolver{Upstream: up.pc.LocalAddr().String(), Blocked: func(string) bool { return true }}
	addr := runResolver(t, r)

	_ = query(t, addr, []byte{0xaa, 0xbb, 0x01}) // too short to be a valid query
	time.Sleep(150 * time.Millisecond)
	if !up.queried.Load() {
		t.Fatal("an unparseable datagram was not forwarded (fail-open broken) — the resolver must not drop it")
	}
}

func TestNxdomainWellFormed(t *testing.T) {
	q := buildQuery(0xabcd, "blocked.example")
	resp := nxdomain(q)
	if resp == nil {
		t.Fatal("nxdomain returned nil for a valid query")
	}
	if resp[0] != 0xab || resp[1] != 0xcd {
		t.Error("txn id not echoed")
	}
	if resp[2]&0x80 == 0 {
		t.Error("QR bit not set")
	}
	if rcode(resp) != 3 {
		t.Errorf("rcode = %d, want 3", rcode(resp))
	}
	// ANCOUNT/NSCOUNT/ARCOUNT all zero; QDCOUNT unchanged (1).
	if resp[5] != 1 || resp[6] != 0 || resp[7] != 0 {
		t.Error("counts wrong (want QDCOUNT=1, ANCOUNT=0)")
	}
	// The question is echoed: the response length equals header+question.
	if len(resp) != len(q) {
		t.Errorf("response len %d, want %d (header+question echoed, no answers)", len(resp), len(q))
	}
	// Too short → nil.
	if nxdomain([]byte{1, 2, 3}) != nil {
		t.Error("a too-short query should yield nil")
	}
}
