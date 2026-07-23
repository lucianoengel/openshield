package gateway

import "strings"

// extractSNI returns the server name (SNI) from a TLS ClientHello at the start of b, or "" if b
// is not a ClientHello, is truncated, carries no server_name, or is malformed.
//
// It is a DEFENSIVE, bounds-checked walk of the ClientHello structure: every length is validated
// against the remaining buffer BEFORE it is used to advance, and no slice is ever sized from an
// attacker-supplied length. A malformed or hostile buffer yields "" — never a panic, never an
// over-read. This is a metadata parse (a hostname), the same class as the gateway's in-process
// HTTP host handling; full content classification stays in the sandboxed worker (D72).
//
// TLS record:      [22][ver:2][len:2] then a handshake message.
// Handshake:       [1=ClientHello][len:3] then the ClientHello body.
// ClientHello:     [ver:2][random:32][sid_len:1][sid][cs_len:2][cs][comp_len:1][comp][ext_len:2][exts]
// Extension:       [type:2][len:2][data]; server_name is type 0x0000, whose data is
//                  [list_len:2] then entries [name_type:1][name_len:2][name].
func extractSNI(b []byte) string {
	// Record header: content type 22 (handshake), 2-byte version, 2-byte length.
	if len(b) < 5 || b[0] != 22 {
		return ""
	}
	recLen := int(b[3])<<8 | int(b[4])
	body := b[5:]
	if recLen < len(body) {
		body = body[:recLen] // don't read past this record
	}

	// Handshake header: type 1 (ClientHello), 3-byte length.
	if len(body) < 4 || body[0] != 1 {
		return ""
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	ch := body[4:]
	if hsLen < len(ch) {
		ch = ch[:hsLen]
	}

	p := 0
	// version(2) + random(32)
	if !advance(&p, ch, 34) {
		return ""
	}
	// session id: 1-byte length + id
	if !skipVector8(&p, ch) {
		return ""
	}
	// cipher suites: 2-byte length + suites
	if !skipVector16(&p, ch) {
		return ""
	}
	// compression methods: 1-byte length + methods
	if !skipVector8(&p, ch) {
		return ""
	}
	// extensions: 2-byte total length + extensions
	if p+2 > len(ch) {
		return ""
	}
	extTotal := int(ch[p])<<8 | int(ch[p+1])
	p += 2
	if p+extTotal > len(ch) {
		extTotal = len(ch) - p // clamp to what we actually have
	}
	exts := ch[p : p+extTotal]

	q := 0
	for q+4 <= len(exts) {
		etype := int(exts[q])<<8 | int(exts[q+1])
		elen := int(exts[q+2])<<8 | int(exts[q+3])
		q += 4
		if q+elen > len(exts) {
			return "" // an extension length that overruns the buffer is malformed
		}
		data := exts[q : q+elen]
		q += elen
		if etype != 0x0000 { // server_name
			continue
		}
		return parseServerName(data)
	}
	return ""
}

// parseServerName reads the server_name extension body:
// [list_len:2] then entries [name_type:1][name_len:2][name]. It returns the first host_name (type 0).
func parseServerName(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	listLen := int(d[0])<<8 | int(d[1])
	list := d[2:]
	if listLen < len(list) {
		list = list[:listLen]
	}
	i := 0
	for i+3 <= len(list) {
		nameType := list[i]
		nameLen := int(list[i+1])<<8 | int(list[i+2])
		i += 3
		if i+nameLen > len(list) {
			return ""
		}
		name := list[i : i+nameLen]
		i += nameLen
		if nameType == 0 { // host_name
			return strings.ToLower(strings.TrimSuffix(string(name), "."))
		}
	}
	return ""
}

// advance moves p forward by n if the buffer has room; returns false if not.
func advance(p *int, b []byte, n int) bool {
	if *p+n > len(b) {
		return false
	}
	*p += n
	return true
}

// skipVector8 skips a 1-byte-length-prefixed vector at p.
func skipVector8(p *int, b []byte) bool {
	if *p+1 > len(b) {
		return false
	}
	n := int(b[*p])
	*p++
	return advance(p, b, n)
}

// skipVector16 skips a 2-byte-length-prefixed vector at p.
func skipVector16(p *int, b []byte) bool {
	if *p+2 > len(b) {
		return false
	}
	n := int(b[*p])<<8 | int(b[*p+1])
	*p += 2
	return advance(p, b, n)
}
