package dnssink

import (
	"encoding/binary"
	"net"
	"strings"
)

// SPLIT-HORIZON ANSWERS (ZT-11).
//
// The bypass guard (ZT-10) stops a client reaching a protected service directly. That closes the wrong
// path and does nothing about the right one: the client still has to be told to use the broker, which in
// practice means a hosts file, a VPN profile, or an internal DNS server somebody else maintains.
//
// Split horizon closes that half. A client asking for a catalogued service name is answered with the
// GATEWAY's address, so the correct path is the default one and needs no client configuration at all.
// Together the two are the pair that makes brokered access ordinary rather than something a user opts
// into: the guard makes going around it fail, and this makes going through it automatic.
//
// IT IS CONVENIENCE, NOT ENFORCEMENT, and the distinction is not a hedge — it decides what an operator
// should rely on. A client that hardcodes an IP, caches an old answer, or uses DoH/DoT never asks this
// resolver anything. The thing that BINDS is the firewall guard; this only removes the reason anybody
// would need to work around it. Documentation must not let the two be read as one control.

// SplitHorizon maps a service name to the address a client should be sent to — in practice, the ZTNA
// gateway's. Names are matched case-insensitively and with or without a trailing dot.
type SplitHorizon map[string]string

// splitTTL is the TTL on a split-horizon answer, in seconds.
//
// Deliberately SHORT. The address is a piece of infrastructure configuration, and a long TTL means a
// client keeps sending traffic to a gateway that has moved — for as long as the TTL says, with no way
// for the operator to shorten it after the fact. Sixty seconds costs a query a minute and buys the
// ability to move a gateway without waiting out every client's cache.
const splitTTL = 60

// Answer returns the address configured for a name, if any.
func (s SplitHorizon) Answer(name string) (string, bool) {
	if len(s) == 0 || name == "" {
		return "", false
	}
	v, ok := s[normalizeName(name)]
	return v, ok
}

// normalizeName lower-cases a name and strips the trailing root dot, so `Payroll.corp.` and
// `payroll.corp` are the same entry. Without it a configuration written one way silently answers
// nothing for clients that ask the other — and every resolver library differs about the dot.
func normalizeName(n string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
}

// ParseSplitHorizon builds a table from a "name=ip,name2=ip" spec.
//
// A malformed entry is an ERROR, never skipped. A skipped name is one a client keeps resolving to the
// real internal address — so it reaches the service DIRECTLY, past the broker, in a deployment that
// believes it configured otherwise. That is precisely the outcome the pair of ZT-10 and this exists to
// prevent, arriving through a typo.
func ParseSplitHorizon(spec string) (SplitHorizon, error) {
	out := SplitHorizon{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, addr, ok := strings.Cut(part, "=")
		name, addr = normalizeName(name), strings.TrimSpace(addr)
		if !ok || name == "" || addr == "" {
			return nil, &parseError{part: part, why: "want name=address"}
		}
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, &parseError{part: part, why: "the address must be a literal IP — a name here " +
				"would need resolving by the resolver that is answering, which is a loop"}
		}
		out[name] = addr
	}
	return out, nil
}

type parseError struct{ part, why string }

func (e *parseError) Error() string {
	return "dnssink: bad split-horizon entry " + e.part + ": " + e.why
}

// splitAnswer builds an A or AAAA response for a query, or nil when it cannot.
//
// It answers ONLY the address family that was asked for. Returning an A record to an AAAA query is not
// merely useless — a dual-stack client that receives it treats the name as having no AAAA and may still
// try the real address over IPv6, which is the direct path this exists to remove. An unmatched family
// gets an empty NOERROR answer instead, which is the correct way to say "this name exists, not in this
// family".
func splitAnswer(query []byte, qtype uint16, addr string) []byte {
	if len(query) < 12 {
		return nil
	}
	qend := questionEnd(query)
	if qend < 0 {
		return nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}
	v4 := ip.To4()

	resp := make([]byte, 0, qend+32)
	resp = append(resp, query[:qend]...)
	resp[2] = 0x81 // QR=1, RD copied as set below
	resp[3] = 0x80 // RA=1, RCODE=0 (NOERROR)
	if query[2]&0x01 != 0 {
		resp[2] |= 0x01 // preserve the client's RD bit
	}
	binary.BigEndian.PutUint16(resp[6:8], 0) // ANCOUNT, fixed up below
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)

	switch {
	case qtype == 1 && v4 != nil:
		resp = appendRR(resp, 1, v4)
	case qtype == 28 && v4 == nil:
		resp = appendRR(resp, 28, ip.To16())
	default:
		// The name exists; not in this family. An empty NOERROR is the answer, and it is the one that
		// stops a dual-stack client falling back to the real address.
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:8], 1)
	return resp
}

// appendRR appends one answer record using a compression pointer to the question's name at offset 12 —
// the standard encoding, and the one every client expects.
func appendRR(resp []byte, rrtype uint16, data []byte) []byte {
	resp = append(resp, 0xc0, 0x0c) // NAME: pointer to offset 12
	resp = binary.BigEndian.AppendUint16(resp, rrtype)
	resp = binary.BigEndian.AppendUint16(resp, 1) // CLASS IN
	resp = binary.BigEndian.AppendUint32(resp, splitTTL)
	resp = binary.BigEndian.AppendUint16(resp, uint16(len(data)))
	return append(resp, data...)
}

// questionEnd returns the offset just past the first question, or -1 if the message is malformed.
func questionEnd(msg []byte) int {
	off := 12
	for {
		if off >= len(msg) {
			return -1
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 {
			return -1 // a compression pointer in a question is malformed
		}
		off += l
	}
	if off+4 > len(msg) {
		return -1
	}
	return off + 4
}
