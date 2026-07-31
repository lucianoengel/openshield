// Package quicpeek reads what a QUIC handshake says about itself, without speaking QUIC (NIPS-12).
//
// WHY THIS RATHER THAN A QUIC STACK. QUIC moved the handshake inside an encrypted transport, and the
// honest consequence for an inline product is stark: everything the gateway learns from a TLS
// ClientHello — the SNI, the client fingerprint — is gone the moment a browser prefers HTTP/3. A
// deployment that inspects HTTP and HTTP/2 and ignores UDP/443 is not covering "the web"; it is covering
// whatever has not upgraded yet, and that share shrinks every year.
//
// Terminating QUIC would mean a QUIC implementation, an HTTP/3 stack, connection state, and a large new
// dependency inside the process that holds the network sockets. This does something much smaller and
// almost as useful: QUIC's FIRST FLIGHT is encrypted with keys derived from a connection ID that travels
// in the clear (RFC 9001 §5.2). Anyone who can see the packet can derive them. So the Initial packet can
// be decrypted, the ClientHello inside it read, and the SAME SNI parser and JA3 fingerprinter the TLS
// path already uses applied to it.
//
// WHAT THIS IS NOT, and the boundary matters more than the capability. This reads the HANDSHAKE. It does
// not decrypt application data, does not track connections, does not reassemble across packets, and
// gives no visibility into anything after the first flight — those keys are negotiated, not derived, and
// nobody outside the endpoints has them. A flow this allows is a flow this product has NOT inspected,
// exactly like a blind CONNECT tunnel, and it must be described that way.
//
// The point of reading it at all is that it is enough to DECIDE: a destination, a client fingerprint, and
// therefore the option to refuse — after which most clients fall back to TCP, onto a path the gateway
// can actually inspect. That fallback is the real mechanism, and it is worth saying plainly that
// "blocking QUIC" is a way of getting traffic back onto an inspectable transport rather than a way of
// inspecting QUIC.
package quicpeek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Version numbers this package knows how to derive keys for.
//
// Version 1 (RFC 9000) and version 2 (RFC 9369) use DIFFERENT salts and different HKDF labels. Deriving
// with the wrong one produces a key that decrypts nothing, which is indistinguishable from a packet that
// is not QUIC — so an unknown version is reported as UNKNOWN rather than as "not QUIC", and the caller
// can tell "we do not speak this" from "there was nothing there".
const (
	Version1 uint32 = 0x00000001
	Version2 uint32 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// ErrNotQUIC means the datagram is not a QUIC long-header Initial packet.
var ErrNotQUIC = errors.New("quicpeek: not a QUIC Initial packet")

// ErrUnknownVersion means it IS QUIC and this package cannot derive its keys.
//
// Distinct from ErrNotQUIC on purpose. A gateway that reported an unrecognised QUIC version as "not
// QUIC" would let a client reach a destination unexamined by doing nothing more exotic than negotiating
// a version this build predates — and the operator would see no signal at all.
var ErrUnknownVersion = errors.New("quicpeek: QUIC version not supported by this build")

// Peek is what one Initial packet reveals.
type Peek struct {
	Version uint32
	// DCID is the destination connection ID, in the clear. It is what the keys are derived from and it
	// is the only stable identifier available before the handshake completes.
	DCID []byte
	// ClientHello is the reassembled TLS ClientHello from the packet's CRYPTO frames, ready for the
	// SAME SNI and JA3 readers the TLS path uses — which is the whole reason to go to this trouble.
	ClientHello []byte
}

// IsQUICInitial reports whether a datagram looks like a QUIC long-header Initial, cheaply and without
// deriving anything.
//
// It is separate from Peek so a hot path can classify a datagram before paying for key derivation and a
// decryption: on a busy gateway most UDP is not QUIC, and the answer "no" should cost a few byte
// comparisons.
func IsQUICInitial(b []byte) bool {
	// Long header form (0x80), fixed bit (0x40), and packet type Initial (bits 4-5 == 00 in v1).
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	switch v {
	case Version1:
		return b[0]&0x30 == 0x00
	case Version2:
		// Version 2 renumbered the packet types; Initial is 0b01.
		return b[0]&0x30 == 0x10
	case 0:
		return false // a Version Negotiation packet, not an Initial
	}
	// A version this build does not know. It is still QUIC, and saying so is the caller's cue to treat
	// it as QUIC rather than as unclassified UDP.
	return true
}

// Peek parses and decrypts a QUIC Initial packet far enough to hand back the ClientHello.
func PeekInitial(datagram []byte) (Peek, error) {
	if !IsQUICInitial(datagram) {
		return Peek{}, ErrNotQUIC
	}
	b := datagram
	if len(b) < 7 {
		return Peek{}, ErrNotQUIC
	}
	version := binary.BigEndian.Uint32(b[1:5])
	off := 5

	dcidLen := int(b[off])
	off++
	if dcidLen > 20 || off+dcidLen > len(b) {
		return Peek{}, ErrNotQUIC
	}
	dcid := b[off : off+dcidLen]
	off += dcidLen

	if off >= len(b) {
		return Peek{}, ErrNotQUIC
	}
	scidLen := int(b[off])
	off++
	if scidLen > 20 || off+scidLen > len(b) {
		return Peek{}, ErrNotQUIC
	}
	off += scidLen

	// Token (Initial only).
	tokenLen, n := readVarint(b[off:])
	if n == 0 {
		return Peek{}, ErrNotQUIC
	}
	off += n
	if tokenLen > uint64(len(b)-off) {
		return Peek{}, ErrNotQUIC
	}
	off += int(tokenLen)

	// Length of (packet number + payload).
	length, n := readVarint(b[off:])
	if n == 0 {
		return Peek{}, ErrNotQUIC
	}
	off += n
	pnOffset := off
	if uint64(pnOffset)+length > uint64(len(b)) {
		return Peek{}, ErrNotQUIC
	}

	salt, err := saltFor(version)
	if err != nil {
		return Peek{Version: version, DCID: dcid}, err
	}
	key, iv, hp, err := clientInitialKeys(salt, dcid, version)
	if err != nil {
		return Peek{Version: version, DCID: dcid}, err
	}

	// HEADER PROTECTION. The sample starts four bytes past the packet-number offset, because the
	// packet-number field may be one to four bytes and the sample is taken as if it were always four —
	// that offset is fixed by the spec precisely so a reader can find it WITHOUT first knowing the
	// length it is trying to recover.
	if pnOffset+4+16 > len(b) {
		return Peek{Version: version, DCID: dcid}, ErrNotQUIC
	}
	sample := b[pnOffset+4 : pnOffset+4+16]
	mask, err := headerMask(hp, sample)
	if err != nil {
		return Peek{Version: version, DCID: dcid}, err
	}

	hdr := make([]byte, pnOffset)
	copy(hdr, b[:pnOffset])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	if pnOffset+pnLen > len(b) {
		return Peek{Version: version, DCID: dcid}, ErrNotQUIC
	}
	pnBytes := make([]byte, pnLen)
	for i := 0; i < pnLen; i++ {
		pnBytes[i] = b[pnOffset+i] ^ mask[1+i]
	}
	var pn uint64
	for _, c := range pnBytes {
		pn = pn<<8 | uint64(c)
	}

	// The AAD is the header WITH protection removed, including the unprotected packet number.
	aad := append(hdr, pnBytes...)
	ctStart := pnOffset + pnLen
	ctEnd := pnOffset + int(length)
	if ctEnd > len(b) || ctStart > ctEnd {
		return Peek{Version: version, DCID: dcid}, ErrNotQUIC
	}
	plaintext, err := openPayload(key, iv, pn, aad, b[ctStart:ctEnd])
	if err != nil {
		// A packet that will not authenticate is one whose keys we derived wrongly or which was not a
		// client Initial at all. It is an error, never an empty ClientHello: reporting "no SNI" for a
		// packet we failed to open would be indistinguishable from a client that sent none.
		return Peek{Version: version, DCID: dcid}, fmt.Errorf("quicpeek: decrypting the Initial: %w", err)
	}

	hello, err := cryptoFrames(plaintext)
	if err != nil {
		return Peek{Version: version, DCID: dcid}, err
	}
	return Peek{Version: version, DCID: dcid, ClientHello: hello}, nil
}

func saltFor(v uint32) ([]byte, error) {
	switch v {
	case Version1:
		return saltV1, nil
	case Version2:
		return saltV2, nil
	}
	return nil, ErrUnknownVersion
}

// clientInitialKeys derives the client's Initial key, IV and header-protection key (RFC 9001 §5.2).
func clientInitialKeys(salt, dcid []byte, version uint32) (key, iv, hp []byte, err error) {
	initial := hkdfExtract(salt, dcid)
	client := hkdfExpandLabel(initial, "client in", 32)
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if version == Version2 {
		// Version 2 changed the labels as well as the salt. Using v1's labels against a v2 packet
		// derives keys that authenticate nothing — which would surface as "not QUIC" and hide an entire
		// protocol version from the gateway.
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	return hkdfExpandLabel(client, keyLabel, 16),
		hkdfExpandLabel(client, ivLabel, 12),
		hkdfExpandLabel(client, hpLabel, 16), nil
}

func headerMask(hp, sample []byte) ([]byte, error) {
	blk, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	blk.Encrypt(out, sample)
	return out, nil
}

func openPayload(key, iv []byte, pn uint64, aad, ct []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	// The packet number is XORed into the RIGHT-ALIGNED end of the IV.
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	return aead.Open(nil, nonce, ct, aad)
}

// cryptoFrames walks the decrypted payload and reassembles the CRYPTO stream.
//
// PADDING and PING frames are skipped, which is most of a client Initial by volume — a client pads to
// 1200 bytes so the path is validated, so a reader that stopped at the first unexpected byte would stop
// almost immediately and return nothing.
func cryptoFrames(p []byte) ([]byte, error) {
	pieces := map[uint64][]byte{}
	var maxEnd uint64
	for i := 0; i < len(p); {
		switch p[i] {
		case 0x00: // PADDING
			i++
		case 0x01: // PING
			i++
		case 0x06: // CRYPTO
			i++
			offset, n := readVarint(p[i:])
			if n == 0 {
				return nil, errTruncatedFrame
			}
			i += n
			length, n := readVarint(p[i:])
			if n == 0 {
				return nil, errTruncatedFrame
			}
			i += n
			if uint64(i)+length > uint64(len(p)) {
				return nil, errTruncatedFrame
			}
			pieces[offset] = p[i : i+int(length)]
			if end := offset + length; end > maxEnd {
				maxEnd = end
			}
			i += int(length)
		default:
			// Any other frame type in a client Initial is either an ACK or something this reader has no
			// need to understand. Stopping is correct: the CRYPTO data gathered so far is what matters,
			// and guessing at a frame's length would desynchronise the walk.
			i = len(p)
		}
	}
	if maxEnd == 0 {
		return nil, errors.New("quicpeek: the Initial carried no CRYPTO frame")
	}
	// A single datagram's CRYPTO frames are contiguous in practice; a gap means the ClientHello spans
	// datagrams, which this deliberately does not reassemble. Returning a partial buffer would hand the
	// TLS readers a truncated message they would report as unparseable — accurate, but it would look
	// like a broken parser rather than a stated limit.
	out := make([]byte, maxEnd)
	filled := make([]bool, maxEnd)
	for off, b := range pieces {
		copy(out[off:], b)
		for j := off; j < off+uint64(len(b)); j++ {
			filled[j] = true
		}
	}
	for _, ok := range filled {
		if !ok {
			return nil, ErrSpansDatagrams
		}
	}
	return out, nil
}

// ErrSpansDatagrams means the ClientHello did not fit in one datagram.
//
// Named and returned rather than papered over: a large ClientHello (many ALPNs, a post-quantum key
// share) genuinely spans packets, and a caller must be able to say "we could not read this one" instead
// of "this one had no SNI".
var ErrSpansDatagrams = errors.New("quicpeek: the ClientHello spans multiple datagrams, which this " +
	"reader does not reassemble")

var errTruncatedFrame = errors.New("quicpeek: truncated CRYPTO frame")

// readVarint decodes a QUIC variable-length integer, returning the value and bytes consumed (0 on
// truncation).
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

// hkdfExtract and hkdfExpandLabel are TLS 1.3's HKDF, which QUIC reuses.
func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // zero-length context

	var out, prev []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, secret)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}
