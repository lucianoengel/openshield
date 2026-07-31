//go:build linux

package gateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/policy"
	"github.com/lucianoengel/openshield/internal/quicpeek"
)

// THE REAL-KERNEL PROOF OF THE INLINE QUIC PLANE (NIPS-12).
//
// Everything else about this plane can be checked in a unit test. Three things cannot, and they are the
// three that decide whether it works at all:
//
//  1. that a nat REDIRECT actually delivers UDP/443 to the plane with its ORIGINAL destination attached;
//  2. that the plane's own forward ESCAPES that redirect (the SO_MARK loop-break) instead of coming back;
//  3. that a reply relayed on the listener reaches the client looking like it came from the destination.
//
// (2) is the one worth the VM. Without the mark exemption the plane redirects its own upstream forward
// into itself, forever, while every log line reports a redirect installed successfully — and the symptom
// is "QUIC stopped working", with nothing anywhere pointing at the rule that caused it.

// --- Fixture: a real QUIC Initial carrying a real ClientHello ------------------------------------------
//
// The packet is BUILT the way an endpoint builds one — CRYPTO frame, padding, AEAD, header protection —
// because there is no way to obtain a genuine client Initial without depending on a QUIC stack, which is
// the dependency internal/quicpeek exists to avoid.
//
// It is a duplicate of the builder in that package's own tests, and a duplicate can drift. So the fixture
// CHECKS ITSELF first (see quicInitialFor): the packet must round-trip through the real reader and yield
// the server name that went into it. A drifted builder fails there, loudly, instead of silently feeding
// this test garbage that the plane then "correctly" fails to decide.

func quicInitialFor(t *testing.T, sni string) []byte {
	t.Helper()
	hello := helloRecordFor(t, sni)
	pkt := buildTestInitial(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, hello[5:]) // strip the TLS record header

	peek, err := quicpeek.PeekInitial(pkt)
	if err != nil {
		t.Fatalf("the fixture does not round-trip through the real reader (%v) — this test's Initial "+
			"builder has drifted from the package it is imitating, and every assertion below would be "+
			"about a packet no client would send", err)
	}
	if got := extractSNI(tlsRecordOf(peek.ClientHello)); got != sni {
		t.Fatalf("the fixture's recovered server name is %q, want %q — the packet is not carrying what "+
			"this test believes it is", got, sni)
	}
	return pkt
}

// helloRecordFor captures the ClientHello a real Go TLS client sends for a given server name.
func helloRecordFor(t *testing.T, sni string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	_ = tc.Handshake() // fails — the ClientHello has already been written, which is all this needs
	select {
	case b := <-got:
		if len(b) < 5 {
			t.Fatal("no ClientHello captured")
		}
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out capturing a ClientHello")
		return nil
	}
}

func buildTestInitial(t *testing.T, dcid, handshake []byte) []byte {
	t.Helper()
	key, iv, hp := testInitialKeys(dcid)

	frames := []byte{0x06}
	frames = appendTestVarint(frames, 0)
	frames = appendTestVarint(frames, uint64(len(handshake)))
	frames = append(frames, handshake...)
	for len(frames) < 1100 {
		frames = append(frames, 0x00) // PADDING, as a real client sends
	}

	var hdr []byte
	hdr = append(hdr, 0xc0) // long header, Initial, 1-byte packet number
	hdr = binary.BigEndian.AppendUint32(hdr, quicpeek.Version1)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // zero-length SCID
	hdr = appendTestVarint(hdr, 0)
	hdr = appendTestVarint(hdr, uint64(1+len(frames)+16))
	pnOffset := len(hdr)
	hdr = append(hdr, 0x00) // packet number 0

	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, iv, frames, hdr)

	pkt := append(append([]byte{}, hdr...), ct...)
	mask := testHeaderMask(t, hp, pkt[pnOffset+4:pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

// testInitialKeys re-derives the RFC 9001 §5.2 client Initial keys.
//
// A duplicate of what internal/quicpeek does, because there is no way to build a client Initial without
// them and exporting a package's crypto internals to serve a test is worse than a copy that CHECKS ITSELF
// — quicInitialFor round-trips every packet this produces through the real reader, so a drifted copy fails
// there rather than quietly feeding this test a packet no client would send.
func testInitialKeys(dcid []byte) (key, iv, hp []byte) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a} // RFC 9001 v1 salt
	m := hmac.New(sha256.New, salt)
	m.Write(dcid)
	client := testExpandLabel(m.Sum(nil), "client in", 32)
	return testExpandLabel(client, "quic key", 16),
		testExpandLabel(client, "quic iv", 12),
		testExpandLabel(client, "quic hp", 16)
}

func testExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)

	var out, prev []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, secret)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func testHeaderMask(t *testing.T, hp, sample []byte) []byte {
	t.Helper()
	blk, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	blk.Encrypt(out, sample)
	return out
}

func appendTestVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	default:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	}
}

// --- The topology ---------------------------------------------------------------------------------------
//
// A client in its own network namespace, reaching a destination THROUGH this host. That is the only
// topology in which this plane is real: a TPROXY divert lives in PREROUTING, which forwarded traffic
// traverses and a host's own locally-generated traffic does not.

const (
	quicNS       = "osq1"
	quicVethHost = "osq-h"
	quicVethNS   = "osq-n"
	quicHostIP   = "10.210.0.1"
	quicClientIP = "10.210.0.2"
	quicDstNet   = "10.211.0.0/24"
	quicDstIP    = "10.211.0.1" // the stand-in QUIC destination
	quicMarkT    = 0x1d7
	quicTableT   = 211
)

func requireQUICPlane(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("QUIC plane kernel test needs root (CAP_NET_ADMIN for IP_TRANSPARENT + TPROXY)")
	}
	for _, tool := range []string{"ip", "iptables", "nc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	pc, err := ListenQUICRedirect("0.0.0.0:0")
	if err != nil {
		t.Skipf("transparent UDP listener unavailable: %v", err)
	}
	pc.Close()
}

// setupQUICTopology builds ns + veth + forwarding + the stand-in destination.
func setupQUICTopology(t *testing.T) {
	t.Helper()
	cleanup := func() {
		tryRun("ip", "netns", "del", quicNS)
		tryRun("ip", "link", "del", quicVethHost)
		tryRun("ip", "addr", "del", quicDstIP+"/32", "dev", "lo")
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "ip", "netns", "add", quicNS)
	run(t, "ip", "link", "add", quicVethHost, "type", "veth", "peer", "name", quicVethNS)
	run(t, "ip", "link", "set", quicVethNS, "netns", quicNS)
	run(t, "ip", "addr", "add", quicHostIP+"/24", "dev", quicVethHost)
	run(t, "ip", "link", "set", quicVethHost, "up")
	run(t, "ip", "netns", "exec", quicNS, "ip", "addr", "add", quicClientIP+"/24", "dev", quicVethNS)
	run(t, "ip", "netns", "exec", quicNS, "ip", "link", "set", quicVethNS, "up")
	run(t, "ip", "netns", "exec", quicNS, "ip", "link", "set", "lo", "up")
	run(t, "ip", "netns", "exec", quicNS, "ip", "route", "add", quicDstNet, "via", quicHostIP)
	run(t, "ip", "addr", "add", quicDstIP+"/32", "dev", "lo")
	run(t, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
}

// fakeQUICServer answers any datagram with a fixed marker, standing in for the real destination.
func fakeQUICServer(t *testing.T) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", quicDstIP+":443")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Skipf("cannot bind the stand-in destination: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = pc.WriteToUDP([]byte("SERVER-REPLY"), from)
			}
		}
	}()
}

// blockOneNamePlane runs a plane that refuses exactly one server name.
func blockOneNamePlane(t *testing.T, blocked string) *QUICPlane {
	t.Helper()
	pol, err := policy.New(context.Background(), "quic-kernel", "1", `package openshield
import rego.v1
decision := {"action":"BLOCK","reason":"blocked name","confidence":1.0} if {
	input.event.host == "`+blocked+`"
}
decision := {"action":"ALLOW","reason":"permitted","confidence":1.0} if {
	input.event.host != "`+blocked+`"
}`)
	if err != nil {
		t.Fatal(err)
	}
	gw := New(sigClassifier{marker: "\x00never\x00"}, pol, noopLedger{}, nil, 2*time.Second)
	return NewQUICPlane(gw, quietLogger())
}

// startPlane brings the plane up behind the divert. divert=false installs NOTHING, which is the mutation
// that proves the rule is what puts the plane in the path.
func startPlane(t *testing.T, p *QUICPlane, divert bool) {
	t.Helper()
	pc, err := ListenQUICRedirect("0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot open the transparent listener: %v", err)
	}
	if err := p.CanForwardTransparently(); err != nil {
		pc.Close()
		t.Skipf("IP_TRANSPARENT forward unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx, pc) }()

	port := pc.LocalAddr().(*net.UDPAddr).Port
	if !divert {
		return
	}
	if err := InstallQUICRedirect(port, quicMarkT, quicTableT, nil); err != nil {
		t.Skipf("cannot install the divert: %v", err)
	}
	t.Cleanup(func() { _ = RemoveQUICRedirect(port, quicMarkT, quicTableT, nil) })
}

// askAsAClient sends one datagram from INSIDE the client namespace and returns whatever comes back.
//
// The client is an ordinary process on an ordinary network. It has no configuration pointing at this
// gateway, no proxy setting and no awareness that anything is between it and the destination — which is
// the entire claim being tested.
func askAsAClient(t *testing.T, datagram []byte, wait time.Duration) string {
	t.Helper()
	f, err := os.CreateTemp("", "quic-initial-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(datagram); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cmd := exec.Command("ip", "netns", "exec", quicNS, "sh", "-c",
		fmt.Sprintf("nc -u -w %d %s 443 < %s", int(wait.Seconds()), quicDstIP, f.Name()))
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out))
}

// THE HEADLINE: an unmodified client's QUIC flow is decided on the server name inside its Initial, and
// refusing it means the flow simply stops.
//
// The client is told nothing. It sends a QUIC Initial to what it believes is a server; the divert hands it
// to the plane, the plane reads the ClientHello out of the encrypted Initial, asks the pipeline, and either
// forwards it or drops it. Both outcomes are checked together because separately each is weak: "blocked
// got no reply" passes if the plumbing is broken end to end, and "allowed got a reply" passes if the plane
// is not deciding anything at all.
func TestAnUnmodifiedClientsQUICFlowIsDecidedOnItsServerName(t *testing.T) {
	requireQUICPlane(t)
	setupQUICTopology(t)
	fakeQUICServer(t)
	p := blockOneNamePlane(t, "evil.example")
	startPlane(t, p, true)

	if got := askAsAClient(t, quicInitialFor(t, "good.example"), 3*time.Second); got != "SERVER-REPLY" {
		t.Fatalf("a PERMITTED QUIC flow got %q, want the destination's reply. Either the plane never "+
			"forwarded it, or the reply did not find its way back to a client that does not know the "+
			"plane exists [decided=%d blocked=%d unreadable=%d failed=%d]", got,
			p.Counts.Decided.Load(), p.Counts.Blocked.Load(), p.Counts.Unreadable.Load(),
			p.Counts.Failed.Load())
	}
	if got := askAsAClient(t, quicInitialFor(t, "evil.example"), 2*time.Second); got != "" {
		t.Fatalf("a REFUSED QUIC flow still got %q from the destination — the policy decision did not "+
			"reach the wire, and the client is talking to a destination this gateway refused "+
			"[decided=%d blocked=%d unreadable=%d failed=%d]", got,
			p.Counts.Decided.Load(), p.Counts.Blocked.Load(), p.Counts.Unreadable.Load(),
			p.Counts.Failed.Load())
	}
	if p.Counts.Blocked.Load() != 1 {
		t.Fatalf("Blocked = %d, want 1", p.Counts.Blocked.Load())
	}
	if p.Counts.Decided.Load() != 2 {
		t.Fatalf("Decided = %d, want 2 — both flows carried a readable handshake, so both were decided "+
			"on policy rather than passed through unread", p.Counts.Decided.Load())
	}
	if u := p.Counts.Unreadable.Load(); u != 0 {
		t.Fatalf("Unreadable = %d: a flow passed UNDECIDED, so an 'allowed' verdict above may just be "+
			"fail-open in disguise", u)
	}
}

// THE DIVERT IS WHAT PUTS THE PLANE IN THE PATH, and this is the mutation that proves it.
//
// With the plane running but no rule installed, the client's QUIC flow reaches the destination directly
// and the plane sees nothing. Without this, the test above could pass on a host where the traffic happened
// to reach the destination by some other route, and every claim made for the plane would be unearned.
func TestWithoutTheDivertTheClientReachesTheDestinationUnexamined(t *testing.T) {
	requireQUICPlane(t)
	setupQUICTopology(t)
	fakeQUICServer(t)
	p := blockOneNamePlane(t, "evil.example")
	startPlane(t, p, false) // MUTATION: the plane runs, nothing is diverted to it

	// The REFUSED name is used deliberately: with the divert installed this flow is dropped, so a reply
	// here can only mean the plane was never in the path.
	if got := askAsAClient(t, quicInitialFor(t, "evil.example"), 3*time.Second); got != "SERVER-REPLY" {
		t.Fatalf("without any divert installed the client got %q rather than reaching the destination "+
			"directly. Something other than this plane is interfering, so the headline test cannot "+
			"attribute its result to the plane either", got)
	}
	if d := p.Counts.Decided.Load(); d != 0 {
		t.Fatalf("the plane decided %d flows with no divert installed — it is receiving traffic by some "+
			"route this test does not control", d)
	}
}

// THE ORIGINAL DESTINATION SURVIVES THE DIVERT.
//
// TPROXY delivers a packet to a socket that is not its destination, so the destination has to be recovered
// from a control message. This is the property whose absence produced the first working version of this
// plane: built on a nat REDIRECT, IP_RECVORIGDSTADDR reported the address AFTER the rewrite, so the plane
// recovered its own listener address, forwarded every flow to itself and looped — measured on this VM as
// one matched packet and 4097 decisions from a single client datagram.
//
// It is asserted against the plane's own flow table rather than through policy, because the destination is
// deliberately not exposed to policy (only the server name is). Checking it here is the direct form of the
// claim anyway: the plane recorded where the client was going.
func TestTheDivertPreservesWhereTheClientWasGoing(t *testing.T) {
	requireQUICPlane(t)
	setupQUICTopology(t)
	fakeQUICServer(t)
	p := blockOneNamePlane(t, "nothing.example")
	startPlane(t, p, true)

	if got := askAsAClient(t, quicInitialFor(t, "any.example"), 3*time.Second); got != "SERVER-REPLY" {
		t.Fatalf("got %q, want the destination's reply", got)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.flows) == 0 {
		t.Fatal("no flow was recorded")
	}
	for key := range p.flows {
		if !strings.HasSuffix(key, "->"+quicDstIP+":443") {
			t.Fatalf("the plane recorded the flow as %q, so it recovered a destination that is not where "+
				"the client was going. Every destination-based decision would then be made about the "+
				"wrong address, and the plane would forward to whatever it recovered — which is how the "+
				"nat-REDIRECT version of this plane came to forward every flow into itself", key)
		}
	}
}
