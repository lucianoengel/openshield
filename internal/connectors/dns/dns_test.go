package dns_test

import (
	"strings"
	"testing"

	dnsc "github.com/lucianoengel/openshield/internal/connectors/dns"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// buildQuery assembles a real DNS query message (header + one question) for a name.
func buildQuery(name string, qtype uint16) []byte {
	msg := []byte{
		0x12, 0x34, // id
		0x01, 0x00, // flags: standard query (QR=0, RD=1)
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar counts
	}
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)                        // root
	msg = append(msg, byte(qtype>>8), byte(qtype)) // qtype
	msg = append(msg, 0x00, 0x01)                  // qclass = IN
	return msg
}

func TestParseQuery(t *testing.T) {
	q, err := dnsc.ParseQuery(buildQuery("mail.example.com", 1))
	if err != nil {
		t.Fatal(err)
	}
	if q.Name != "mail.example.com" {
		t.Errorf("name = %q, want mail.example.com", q.Name)
	}
	if q.QType != 1 {
		t.Errorf("qtype = %d, want 1 (A)", q.QType)
	}

	// The connector produces a NetworkSubject Event carrying the queried name as metadata.
	ev := dnsc.ToEvent("flow-1", "10.0.0.5", q)
	if ev.GetKind() != corev1.EventKind_EVENT_KIND_DNS_QUERY {
		t.Errorf("kind = %v, want DNS_QUERY", ev.GetKind())
	}
	if ev.GetNetwork().GetSniHost() != "mail.example.com" {
		t.Errorf("event host = %q, want the queried name", ev.GetNetwork().GetSniHost())
	}
	if ev.GetNetwork().GetDstPort() != 53 {
		t.Errorf("dst port = %d, want 53", ev.GetNetwork().GetDstPort())
	}
}

// Malformed messages are rejected, never parsed to a partial/empty name (D17).
func TestParseQueryRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":          {0x00, 0x01},
		"no question":        {0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0},
		"a response not qry": func() []byte { m := buildQuery("x.com", 1); m[2] |= 0x80; return m }(),
		"truncated name":     {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x05, 'a', 'b'}, // label len 5 but only 2 bytes
		"pointer in qname":   {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c},
		// A pointer byte (0xc0) followed by ENOUGH bytes that the label-bound check would
		// pass — so ONLY the pointer check can reject it. Without that check the parser
		// would misread the pointer as a 192-byte label and accept a garbage name.
		"pointer with room": func() []byte {
			m := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0}
			m = append(m, make([]byte, 192)...) // 192 filler bytes so off+l fits
			m = append(m, 0x00, 0x00, 0x01, 0x00, 0x01)
			return m
		}(),
	}
	for name, msg := range cases {
		if _, err := dnsc.ParseQuery(msg); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

// The tunnel heuristic separates a normal name from an exfil channel: a long, high-entropy
// subdomain scores high; ordinary names score low.
func TestTunnelScore(t *testing.T) {
	normal := []string{"www.google.com", "mail.example.com", "api.github.com", "cdn.jsdelivr.net"}
	for _, n := range normal {
		if s := dnsc.TunnelScore(n); s > 0.3 {
			t.Errorf("normal name %q scored %v — too high", n, s)
		}
	}
	// A base32-ish encoded 40-char label under a domain = the classic exfil shape.
	exfil := "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dypb2ha5dinfzq.evil.example.com"
	if s := dnsc.TunnelScore(exfil); s < 0.5 {
		t.Errorf("exfil-shaped name scored %v — too low to flag", s)
	}
}
