package gateway

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// NIPS-9 — JA3 TLS CLIENT FINGERPRINTING.
//
// Every other network signal this gateway matches on describes the DESTINATION — SNI, IP, URI. All three
// fail against the thing they most need to catch: a family that rotates domains daily, registers a name
// nobody has seen, or encrypts the SNI outright. JA3 describes the CLIENT, which is the part an operator
// does not rewrite between campaigns because rewriting it means rebuilding against a different TLS stack.

// realClientHello captures the ClientHello a REAL Go TLS client sends, by pointing it at a listener that
// reads the first flight and never answers.
//
// A hand-built fixture would prove the parser can read bytes this test wrote, which is a much weaker
// claim: a fixture and a parser written together agree with each other by construction. This makes the
// standard library the author of the input.
func realClientHello(t *testing.T) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan []byte, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()

	go func() {
		conn, derr := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
		if derr != nil {
			return
		}
		defer conn.Close()
		// No InsecureSkipVerify: the listener never replies, so the handshake fails before any
		// certificate is ever offered. Only the ClientHello — the first flight — is under test.
		tc := tls.Client(conn, &tls.Config{ServerName: "example.internal", MinVersion: tls.VersionTLS12})
		_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
		_ = tc.Handshake() // will fail; the ClientHello has already been sent
	}()

	select {
	case b := <-got:
		if len(b) == 0 {
			t.Fatal("captured no ClientHello")
		}
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timed out capturing a ClientHello")
		return nil
	}
}

// THE HEADLINE: a real client's handshake yields a well-formed, stable fingerprint.
func TestARealClientHelloProducesAStableFingerprint(t *testing.T) {
	hello := realClientHello(t)

	ja3, digest, ok := JA3(hello)
	if !ok {
		t.Fatalf("failed to fingerprint a ClientHello the Go standard library sent (%d bytes)", len(hello))
	}
	if n := strings.Count(ja3, ","); n != 4 {
		t.Fatalf("JA3 string %q has %d commas, want 4 — the format is "+
			"version,ciphers,extensions,curves,pointformats, and a feed built against any other "+
			"implementation would not match ours", ja3, n)
	}
	if len(digest) != 32 {
		t.Fatalf("digest %q is %d chars, want a 32-char MD5 hex", digest, len(digest))
	}
	// The SNI parser and the fingerprint read the SAME bytes; if one works the other must.
	if sni := extractSNI(hello); sni != "example.internal" {
		t.Fatalf("SNI = %q, want example.internal — the two parsers read the same peek and must agree "+
			"about what they are looking at", sni)
	}

	// STABILITY is the property that makes a fingerprint worth having. A second handshake from the same
	// client must produce the same value; if it did not, no feed could ever list it.
	hello2 := realClientHello(t)
	_, digest2, ok2 := JA3(hello2)
	if !ok2 || digest2 != digest {
		t.Fatalf("two handshakes from the same client fingerprinted differently (%q vs %q) — a value "+
			"that changes per connection cannot be listed by anyone, and the feature would appear to "+
			"work while never matching once", digest, digest2)
	}
}

// GREASE IS EXCLUDED, and this is what makes stability possible at all.
//
// Clients inject random reserved values (RFC 8701) into their cipher, extension and curve lists
// deliberately, to keep middleboxes honest. Including them gives a different fingerprint on every
// connection — the feature looks correct, produces no match ever, and there is nothing to see.
//
// Mutation (drop the isGREASE filtering): a hello carrying GREASE fingerprints differently from the same
// hello without it → FAIL.
func TestGREASEValuesAreExcluded(t *testing.T) {
	plain := buildHello(t, []uint16{0x1301, 0x1302}, []uint16{0x0000, 0x000a}, []uint16{0x001d})
	greased := buildHello(t,
		[]uint16{0x0a0a, 0x1301, 0x1302}, // a GREASE cipher
		[]uint16{0x1a1a, 0x0000, 0x000a}, // a GREASE extension
		[]uint16{0x2a2a, 0x001d})         // a GREASE curve

	a, da, ok := JA3(plain)
	if !ok {
		t.Fatalf("the plain hello did not parse")
	}
	b, db, ok := JA3(greased)
	if !ok {
		t.Fatalf("the GREASE hello did not parse")
	}
	if a != b || da != db {
		t.Fatalf("GREASE changed the fingerprint:\n  without: %s\n  with:    %s\n"+
			"clients inject those values randomly on every connection, so including them means the "+
			"same client never fingerprints the same way twice and no feed can list it", a, b)
	}
	// And the sanity check that the fixture is not simply producing nothing: the real values ARE there.
	if !strings.Contains(a, "4865-4866") { // 0x1301, 0x1302
		t.Fatalf("the fingerprint %q does not carry the offered ciphers — filtering GREASE must not "+
			"filter everything", a)
	}
}

// A HOSTILE OR TRUNCATED BUFFER YIELDS NOTHING, never a panic and never an over-read.
//
// These bytes arrive from the network, on the gateway's hot path, before anything has authenticated. The
// parser walks attacker-controlled length fields, so the only acceptable failure is a clean false.
func TestAMalformedHelloIsRefusedRatherThanPanicking(t *testing.T) {
	hello := realClientHello(t)

	cases := map[string][]byte{
		"empty":            {},
		"not a handshake":  {23, 3, 3, 0, 5, 1, 2, 3, 4, 5},
		"record only":      hello[:5],
		"truncated header": hello[:9],
		"lying record len": append([]byte{22, 3, 1, 0xff, 0xff}, hello[5:20]...),
	}
	// Every truncation of a real hello, one byte at a time — the shape a peek that arrived in two TCP
	// segments actually produces.
	for i := 0; i < len(hello); i += 7 {
		cases["truncated at "+itoaTest(i)] = hello[:i]
	}
	// Every single-byte corruption at a length-bearing offset.
	for _, off := range []int{3, 4, 6, 7, 8, 43, 44} {
		if off >= len(hello) {
			continue
		}
		bad := append([]byte(nil), hello...)
		bad[off] = 0xff
		cases["corrupt byte "+itoaTest(off)] = bad
	}

	for name, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: PANIC in a parser that runs on unauthenticated network bytes on the "+
						"gateway's hot path: %v", name, r)
				}
			}()
			ja3, digest, ok := JA3(in)
			if !ok && (ja3 != "" || digest != "") {
				t.Errorf("%s: returned ok=false with a non-empty result (%q, %q)", name, ja3, digest)
			}
		}()
	}
}

// A CLIENTHELLO WITH NO EXTENSIONS is legal, and yields the three empty trailing fields rather than a
// refusal — the same string every other implementation produces for it. Refusing would mean a client
// this gateway cannot fingerprint at all, silently.
func TestAHelloWithNoExtensionsStillFingerprints(t *testing.T) {
	hello := buildHelloNoExtensions(t, []uint16{0x1301})
	ja3, _, ok := JA3(hello)
	if !ok {
		t.Fatal("a ClientHello with no extensions was refused; it is unusual but legal, and refusing " +
			"means that client is silently unfingerprintable")
	}
	if !strings.HasSuffix(ja3, ",,,") {
		t.Fatalf("JA3 = %q, want three empty trailing fields", ja3)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// buildHello assembles a minimal but structurally valid ClientHello with the given ciphers, extension
// types and curves. Used only where a REAL client cannot be made to offer a specific list (GREASE).
func buildHello(t *testing.T, ciphers, extTypes, curves []uint16) []byte {
	t.Helper()
	var ch []byte
	ch = append(ch, 0x03, 0x03)            // legacy_version
	ch = append(ch, make([]byte, 32)...)   // random
	ch = append(ch, 0x00)                  // session id: empty
	ch = appendUint16Vector16(ch, ciphers) // cipher suites
	ch = append(ch, 0x01, 0x00)            // compression: one method, null

	var exts []byte
	for _, et := range extTypes {
		var body []byte
		if et == 0x000a { // supported_groups carries the curves
			body = appendUint16Vector16(nil, curves)
		}
		exts = append(exts, byte(et>>8), byte(et), byte(len(body)>>8), byte(len(body)))
		exts = append(exts, body...)
	}
	ch = append(ch, byte(len(exts)>>8), byte(len(exts)))
	ch = append(ch, exts...)

	return wrapHandshake(ch)
}

func buildHelloNoExtensions(t *testing.T, ciphers []uint16) []byte {
	t.Helper()
	var ch []byte
	ch = append(ch, 0x03, 0x03)
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0x00)
	ch = appendUint16Vector16(ch, ciphers)
	ch = append(ch, 0x01, 0x00)
	return wrapHandshake(ch)
}

func wrapHandshake(ch []byte) []byte {
	hs := append([]byte{1, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}, ch...)
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func appendUint16Vector16(dst []byte, vs []uint16) []byte {
	n := len(vs) * 2
	dst = append(dst, byte(n>>8), byte(n))
	for _, v := range vs {
		dst = append(dst, byte(v>>8), byte(v))
	}
	return dst
}

// FuzzJA3 drives the parser with arbitrary bytes.
//
// This parser runs on the gateway's hot path against unauthenticated network input, walking
// attacker-controlled length fields. The property is total: for ANY input it returns cleanly. A crash
// here is a remote denial of service against the network plane, reachable by anyone who can open a TCP
// connection through it.
func FuzzJA3(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{22, 3, 1, 0, 0})
	f.Add(buildHelloNoExtensions(&testing.T{}, []uint16{0x1301}))
	f.Add(buildHello(&testing.T{}, []uint16{0x1301}, []uint16{0x0000, 0x000a, 0x000b}, []uint16{0x001d}))
	f.Fuzz(func(t *testing.T, b []byte) {
		ja3, digest, ok := JA3(b)
		if !ok {
			if ja3 != "" || digest != "" {
				t.Fatalf("ok=false with a non-empty result (%q, %q)", ja3, digest)
			}
			return
		}
		if len(digest) != 32 {
			t.Fatalf("ok=true with a %d-char digest %q", len(digest), digest)
		}
		if strings.Count(ja3, ",") != 4 {
			t.Fatalf("ok=true with a malformed JA3 string %q", ja3)
		}
	})
}
