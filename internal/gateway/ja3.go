package gateway

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 CLIENT FINGERPRINTING (NIPS-9).
//
// WHY IT EARNS ITS PLACE. Every other network signal this gateway matches on describes the DESTINATION —
// the SNI, the IP, the URI. All three fail against the thing they most need to catch: a family that
// rotates domains daily, registers a name nobody has ever seen, or encrypts the SNI outright. JA3
// describes the CLIENT instead, and the client is the part the operator of that malware does not rewrite
// between campaigns, because rewriting it means rebuilding against a different TLS stack.
//
// WHAT IT IS. The MD5 of a comma-joined string built from the ClientHello:
//
//	SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// each field a hyphen-joined list of decimal numbers, in the order the client offered them. MD5 is not a
// security choice here and is not defended as one: JA3 is an interoperable identifier and a different
// hash would produce fingerprints that match nobody else's feed, which is the entire point of having one.
//
// WHAT IT IS NOT. It is a fingerprint of a TLS LIBRARY AT A VERSION, not of a program and not of a
// person. Every Go 1.22 client shares one; so does every copy of a given browser build. That makes it a
// WEAK signal alone — high recall, poor precision — and the honest use is as a corroborating axis
// alongside destination intel, not as a standalone block list. It is also not an identifier under D23:
// it says nothing about who is at the keyboard.
//
// GREASE IS EXCLUDED (RFC 8701). Clients deliberately inject random reserved values into their cipher,
// extension and curve lists to keep middleboxes honest. Including them would make the same client produce
// a different fingerprint on every connection — the feature would appear to work, produce no matches
// ever, and there would be nothing to see.

// greaseValues are the sixteen reserved GREASE code points, 0x?A?A (RFC 8701).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

// JA3 returns the JA3 string and its MD5 hex digest for a TLS ClientHello at the start of b.
//
// ok is false when b is not a parseable ClientHello. It walks the same defensive, bounds-checked
// structure as extractSNI: every length is validated against the remaining buffer before it is used, and
// no slice is ever sized from an attacker-supplied length. A malformed or hostile buffer yields ok=false
// — never a panic, never an over-read. This is a metadata parse of fixed-width integers; content
// classification stays in the sandboxed worker (D72).
func JA3(b []byte) (ja3 string, digest string, ok bool) {
	ch, ok := clientHelloBody(b)
	if !ok {
		return "", "", false
	}
	p := 0
	if p+2 > len(ch) {
		return "", "", false
	}
	// The version in the JA3 string is the ClientHello's legacy_version, not the true negotiated one.
	// TLS 1.3 clients all report 0x0303 here and carry the real version in supported_versions; that is
	// what every other JA3 implementation hashes, and matching them matters more than being more
	// correct alone.
	version := int(ch[p])<<8 | int(ch[p+1])
	if !advance(&p, ch, 34) { // version(2) + random(32)
		return "", "", false
	}
	if !skipVector8(&p, ch) { // session id
		return "", "", false
	}

	ciphers, ok := readUint16Vector16(&p, ch)
	if !ok {
		return "", "", false
	}
	if !skipVector8(&p, ch) { // compression methods
		return "", "", false
	}

	// Extensions are OPTIONAL in the wire format. A ClientHello without them is unusual but legal, and
	// yields the three empty trailing fields rather than a failure — the same string every other
	// implementation produces for it.
	var extTypes, curves, pointFormats []uint16
	if p+2 <= len(ch) {
		extTotal := int(ch[p])<<8 | int(ch[p+1])
		p += 2
		if p+extTotal > len(ch) {
			extTotal = len(ch) - p
		}
		exts := ch[p : p+extTotal]
		q := 0
		for q+4 <= len(exts) {
			etype := uint16(exts[q])<<8 | uint16(exts[q+1])
			elen := int(exts[q+2])<<8 | int(exts[q+3])
			q += 4
			if q+elen > len(exts) {
				return "", "", false // an extension length that overruns the buffer is malformed
			}
			data := exts[q : q+elen]
			q += elen
			if isGREASE(etype) {
				continue
			}
			extTypes = append(extTypes, etype)
			switch etype {
			case 0x000a: // supported_groups (elliptic curves): [list_len:2] then 2-byte curve ids
				curves = append(curves, filterGREASE(readUint16List16(data))...)
			case 0x000b: // ec_point_formats: [list_len:1] then 1-byte formats
				pointFormats = append(pointFormats, readUint8List8(data)...)
			}
		}
	}

	ja3 = strings.Join([]string{
		strconv.Itoa(version),
		joinUint16(filterGREASE(ciphers)),
		joinUint16(extTypes),
		joinUint16(curves),
		joinUint16(pointFormats),
	}, ",")
	sum := md5.Sum([]byte(ja3)) //nolint:gosec // JA3 is defined as MD5; a different hash matches no feed
	return ja3, hex.EncodeToString(sum[:]), true
}

// clientHelloBody unwraps the TLS record and handshake headers and returns the ClientHello body.
func clientHelloBody(b []byte) ([]byte, bool) {
	if len(b) < 5 || b[0] != 22 { // handshake record
		return nil, false
	}
	recLen := int(b[3])<<8 | int(b[4])
	body := b[5:]
	if recLen < len(body) {
		body = body[:recLen]
	}
	if len(body) < 4 || body[0] != 1 { // ClientHello
		return nil, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	ch := body[4:]
	if hsLen < len(ch) {
		ch = ch[:hsLen]
	}
	return ch, true
}

// readUint16Vector16 reads a 2-byte-length-prefixed vector of 2-byte values at p and advances past it.
func readUint16Vector16(p *int, b []byte) ([]uint16, bool) {
	if *p+2 > len(b) {
		return nil, false
	}
	n := int(b[*p])<<8 | int(b[*p+1])
	*p += 2
	if *p+n > len(b) {
		return nil, false
	}
	v := readUint16Slice(b[*p : *p+n])
	*p += n
	return v, true
}

// readUint16List16 reads a 2-byte-length-prefixed list of 2-byte values from the START of d (the shape
// of the supported_groups extension body). A truncated list yields what fits, never an over-read.
func readUint16List16(d []byte) []uint16 {
	if len(d) < 2 {
		return nil
	}
	n := int(d[0])<<8 | int(d[1])
	body := d[2:]
	if n < len(body) {
		body = body[:n]
	}
	return readUint16Slice(body)
}

// readUint8List8 reads a 1-byte-length-prefixed list of 1-byte values (ec_point_formats), widened to
// uint16 so every JA3 field renders through one path.
func readUint8List8(d []byte) []uint16 {
	if len(d) < 1 {
		return nil
	}
	n := int(d[0])
	body := d[1:]
	if n < len(body) {
		body = body[:n]
	}
	out := make([]uint16, 0, len(body))
	for _, v := range body {
		out = append(out, uint16(v))
	}
	return out
}

func readUint16Slice(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return out
}

func filterGREASE(vs []uint16) []uint16 {
	out := vs[:0:0]
	for _, v := range vs {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinUint16(vs []uint16) string {
	if len(vs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range vs {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(v)))
	}
	return b.String()
}

// ja3Of returns the fingerprint digest for peeked bytes, or "" when they are not a ClientHello.
//
// A convenience over JA3 for the hot path, which wants the digest and nothing else. The full string is
// kept available because a fingerprint an analyst cannot expand is one they cannot check against another
// tool's — and a digest that disagrees with someone else's feed is worth being able to diagnose.
func ja3Of(peeked []byte) (string, bool) {
	_, digest, ok := JA3(peeked)
	if !ok {
		return "", false
	}
	return digest, true
}
