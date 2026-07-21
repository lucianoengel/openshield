// Package dns is a DNS-query connector (Phase C — network breadth). It parses a DNS
// query off the wire into a NetworkSubject Event so DNS resolution enters the SAME
// pipeline as file and HTTP events — enabling egress policy on resolved names and
// detection of DNS tunneling / exfiltration (a long, high-entropy query name is the
// classic covert channel).
//
// It is a pure parser + Event producer: no sockets here, so the wire-format handling
// (the untrusted-bytes surface) is tested in ordinary Go, exactly as the fanotify and
// gateway connectors separate parsing from I/O. The queried name is METADATA — a policy
// decides on it — carried in NetworkSubject.sni_host (the flow's destination name),
// never body content (D10/D29).
package dns

import (
	"fmt"
	"math"
	"strings"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Query is the parsed content of a DNS question — metadata only.
type Query struct {
	Name  string // the queried domain, lowercased, without the trailing dot
	QType uint16 // 1=A, 28=AAAA, 16=TXT, 255=ANY, …
}

// maxName bounds a decoded name (RFC 1035 caps a name at 255 octets); a decoder that
// does not bound the name is a memory/loop DoS on crafted input.
const maxName = 255

// ParseQuery decodes the first question from a DNS message. It reads ONLY the question
// section — it does not follow compression pointers (a query's QNAME is not compressed),
// which also removes the pointer-loop DoS. A malformed or truncated message is an error,
// never a partial/empty name silently treated as a valid query (D17).
func ParseQuery(msg []byte) (Query, error) {
	if len(msg) < 12 {
		return Query{}, fmt.Errorf("dns: message shorter than header")
	}
	qdcount := int(msg[4])<<8 | int(msg[5])
	if qdcount < 1 {
		return Query{}, fmt.Errorf("dns: no question in message")
	}
	// QR bit (msg[2]&0x80): 0 = query. We only produce events for QUERIES.
	if msg[2]&0x80 != 0 {
		return Query{}, fmt.Errorf("dns: message is a response, not a query")
	}

	off := 12
	var labels []string
	total := 0
	for {
		if off >= len(msg) {
			return Query{}, fmt.Errorf("dns: truncated name")
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break // root label ends the name
		}
		if l&0xc0 != 0 {
			// A compression pointer in a QNAME is malformed; reject rather than chase it.
			return Query{}, fmt.Errorf("dns: unexpected pointer in question name")
		}
		if off+l > len(msg) {
			return Query{}, fmt.Errorf("dns: label runs past message")
		}
		total += l + 1
		if total > maxName {
			return Query{}, fmt.Errorf("dns: name exceeds %d octets", maxName)
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+l])))
		off += l
	}
	if off+4 > len(msg) {
		return Query{}, fmt.Errorf("dns: truncated question (no qtype/qclass)")
	}
	qtype := uint16(msg[off])<<8 | uint16(msg[off+1])
	name := strings.Join(labels, ".")
	if name == "" {
		return Query{}, fmt.Errorf("dns: empty query name (root)")
	}
	return Query{Name: name, QType: qtype}, nil
}

// ToEvent builds a NetworkSubject Event from a parsed query. The queried name goes in
// sni_host (the flow's destination name); protocol udp, dst_port 53. flowID is the
// connector's opaque handle (the caller mints it, as the gateway does per request).
func ToEvent(flowID, srcIP string, q Query) *corev1.Event {
	return &corev1.Event{
		ConnectorId: "dns",
		EventId:     "dns-" + flowID,
		Kind:        corev1.EventKind_EVENT_KIND_DNS_QUERY,
		Target: &corev1.Event_Network{Network: &corev1.NetworkSubject{
			FlowId:   flowID,
			SrcIp:    srcIP,
			DstPort:  53,
			Protocol: "udp",
			SniHost:  q.Name,
		}},
	}
}

// TunnelScore rates how likely a query name is DNS tunneling / exfiltration, in [0,1]. A
// covert channel encodes data in long, high-entropy subdomain labels; a normal name is
// short, low-entropy, dictionary-ish. This is a heuristic SIGNAL for a policy, not a
// verdict — the policy (or a downstream classifier) decides. Two independent signals are
// combined: the longest label's length and its Shannon entropy over the character set.
func TunnelScore(name string) float64 {
	longest := ""
	for _, l := range strings.Split(name, ".") {
		if len(l) > len(longest) {
			longest = l
		}
	}
	// Length signal: labels over ~30 chars are unusual for legitimate names; ramp to 1
	// by the 63-char label maximum.
	lenSig := clamp01(float64(len(longest)-20) / 43.0)
	// Entropy signal: high per-character entropy (near log2(charset)) indicates encoded
	// data rather than words. Normalize against 4.5 bits (typical of base32/hex-ish data).
	entSig := clamp01(shannon(longest) / 4.5)
	// Combine: tunneling needs BOTH length AND entropy — a long dictionary word is not
	// exfil, and a short random token is not a channel. Use the product, so either being
	// low keeps the score low.
	return lenSig * entSig
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
