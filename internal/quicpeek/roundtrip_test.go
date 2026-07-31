package quicpeek

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
)

// RECOVERING THE CLIENTHELLO FROM A QUIC INITIAL.
//
// The vectors next door anchor the key schedule to RFC 9001. This anchors the packet handling: it BUILDS
// an Initial the way an endpoint does — CRYPTO frame, padding to 1200, AEAD, header protection — and
// requires the reader to get the ClientHello back out.
//
// It is a round trip, and a round trip proves less than a published vector. It is here because the
// alternative is worse: the only other way to get a real client Initial is to depend on a QUIC library,
// which is precisely the dependency this package exists to avoid. The split is deliberate — the
// CRYPTOGRAPHY is checked against the spec's own numbers, and only the FRAMING is round-tripped.

// buildInitial assembles a client Initial carrying the given crypto payload.
func buildInitial(t *testing.T, dcid, cryptoPayload []byte, version uint32) []byte {
	t.Helper()
	salt, err := saltFor(version)
	if err != nil {
		t.Fatal(err)
	}
	key, iv, hp, err := clientInitialKeys(salt, dcid, version)
	if err != nil {
		t.Fatal(err)
	}

	// One CRYPTO frame at offset 0, then PADDING — the shape a real client sends, because it must pad
	// the datagram to 1200 bytes for path validation.
	frames := []byte{0x06}
	frames = appendVarint(frames, 0)
	frames = appendVarint(frames, uint64(len(cryptoPayload)))
	frames = append(frames, cryptoPayload...)
	for len(frames) < 1100 {
		frames = append(frames, 0x00)
	}

	firstByte := byte(0xc0) // long header, fixed bit, Initial, 1-byte packet number
	if version == Version2 {
		firstByte = 0xd0 // version 2 renumbered Initial to 0b01
	}
	var hdr []byte
	hdr = append(hdr, firstByte)
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // zero-length SCID
	hdr = appendVarint(hdr, 0)
	// length = packet number (1) + ciphertext (frames + 16-byte tag)
	hdr = appendVarint(hdr, uint64(1+len(frames)+16))
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
	nonce := make([]byte, len(iv))
	copy(nonce, iv) // packet number 0, so the IV is unchanged
	ct := aead.Seal(nil, nonce, frames, hdr)

	pkt := append(append([]byte{}, hdr...), ct...)
	// Header protection, applied last, exactly as an endpoint does.
	sample := pkt[pnOffset+4 : pnOffset+4+16]
	mask, err := headerMask(hp, sample)
	if err != nil {
		t.Fatal(err)
	}
	pkt[0] ^= mask[0] & 0x0f
	pkt[pnOffset] ^= mask[1]
	return pkt
}

func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v < 1<<30:
		return append(b, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		b = append(b, 0xc0)
		return binary.BigEndian.AppendUint64(b[:len(b)-1], v|0xc0<<56)
	}
}

// THE HEADLINE: a QUIC Initial gives up the ClientHello inside it.
func TestAQUICInitialGivesUpItsClientHello(t *testing.T) {
	for _, version := range []uint32{Version1, Version2} {
		v := version
		t.Run(map[uint32]string{Version1: "v1", Version2: "v2"}[v], func(t *testing.T) {
			dcid := make([]byte, 8)
			if _, err := rand.Read(dcid); err != nil {
				t.Fatal(err)
			}
			hello := []byte("\x01\x00\x00\x2fTHIS-IS-A-CLIENT-HELLO-STANDING-IN-FOR-TLS")
			pkt := buildInitial(t, dcid, hello, v)

			if !IsQUICInitial(pkt) {
				t.Fatal("a well-formed Initial was not classified as one")
			}
			got, err := PeekInitial(pkt)
			if err != nil {
				t.Fatalf("peeking: %v — everything a gateway learns from a TLS ClientHello is inside "+
					"this packet, and unreadable means UDP/443 is a hole in the coverage", err)
			}
			if got.Version != v {
				t.Errorf("version = %#x, want %#x", got.Version, v)
			}
			if !bytes.Equal(got.DCID, dcid) {
				t.Errorf("dcid = %x, want %x", got.DCID, dcid)
			}
			if !bytes.Equal(got.ClientHello, hello) {
				t.Fatalf("recovered %q, want the ClientHello that was sent", got.ClientHello)
			}
		})
	}
}

// A DATAGRAM THAT IS NOT QUIC IS REJECTED CHEAPLY, and one that is QUIC but will not authenticate is an
// ERROR rather than an empty ClientHello.
//
// The distinction is the point: reporting "no SNI" for a packet we failed to open is indistinguishable
// from a client that sent none, and one of those is a flow the gateway examined and the other is a flow
// it did not.
func TestAFailedDecryptionIsAnErrorRatherThanAnEmptyResult(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pkt := buildInitial(t, dcid, []byte("hello"), Version1)

	// Corrupt the ciphertext so the AEAD tag fails.
	bad := append([]byte{}, pkt...)
	bad[len(bad)-20] ^= 0xff
	got, err := PeekInitial(bad)
	if err == nil {
		t.Fatal("a packet whose AEAD tag does not verify was accepted")
	}
	if got.ClientHello != nil {
		t.Fatalf("a failed decryption returned a ClientHello (%q) — 'no SNI' and 'we could not read it' "+
			"are opposite answers, and one of them means the flow was never examined", got.ClientHello)
	}
	// The version and DCID ARE still reported: they were in the clear, and a caller deciding whether to
	// refuse the flow can use them even when the handshake could not be read.
	if got.Version != Version1 || !bytes.Equal(got.DCID, dcid) {
		t.Error("the cleartext header fields were discarded along with the failure — a caller refusing " +
			"an unreadable QUIC flow still needs to know it was QUIC")
	}

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short header", []byte{0x40, 0x01, 0x02}},
		{"http", []byte("GET / HTTP/1.1\r\n\r\n")},
		{"version negotiation", []byte{0xc0, 0, 0, 0, 0, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0}},
	} {
		if IsQUICInitial(tc.in) {
			t.Errorf("%s was classified as a QUIC Initial", tc.name)
		}
		if _, err := PeekInitial(tc.in); !errors.Is(err, ErrNotQUIC) {
			t.Errorf("%s gave %v, want ErrNotQUIC", tc.name, err)
		}
	}
}

// A CLIENTHELLO THAT SPANS DATAGRAMS IS REPORTED AS SUCH, never as a short one.
//
// A large ClientHello — many ALPNs, a post-quantum key share — genuinely spans packets. Returning the
// fragment would hand the TLS readers a truncated message they would report as unparseable: accurate,
// but it reads as a broken parser rather than a stated limit of this reader.
//
// Mutation (return the partial buffer instead of ErrSpansDatagrams): the caller cannot tell a truncated
// read from a malformed handshake → FAIL.
func TestASplitClientHelloIsReportedRatherThanTruncated(t *testing.T) {
	// A CRYPTO frame at offset 100 with nothing before it: the first part went in another datagram.
	frames := []byte{0x06}
	frames = appendVarint(frames, 100)
	frames = appendVarint(frames, 5)
	frames = append(frames, []byte("later")...)

	_, err := cryptoFrames(frames)
	if !errors.Is(err, ErrSpansDatagrams) {
		t.Fatalf("a CRYPTO frame starting at a non-zero offset gave %v, want ErrSpansDatagrams — "+
			"returning the fragment hands the TLS reader a truncated message it reports as "+
			"unparseable, which reads as a broken parser rather than a stated limit", err)
	}
}

// PADDING IS SKIPPED, which is most of a client Initial by volume.
//
// A client pads to 1200 bytes so the path is validated, so a frame walker that stopped at the first
// unexpected byte would stop almost immediately and return nothing — on every real packet.
func TestPaddingDoesNotStopTheFrameWalk(t *testing.T) {
	frames := make([]byte, 200) // 200 PADDING frames first
	frames = append(frames, 0x06)
	frames = appendVarint(frames, 0)
	frames = appendVarint(frames, 3)
	frames = append(frames, []byte("abc")...)

	got, err := cryptoFrames(frames)
	if err != nil {
		t.Fatalf("padding before the CRYPTO frame broke the walk: %v — a client pads to 1200 bytes, so "+
			"this is every real packet", err)
	}
	if string(got) != "abc" {
		t.Fatalf("recovered %q, want abc", got)
	}
}

// FuzzPeekInitial drives the reader with arbitrary datagrams.
//
// This runs on UDP the gateway did not ask for, before anything has authenticated, and it walks
// attacker-controlled length fields through a decryption. A crash here is a remote denial of service
// against the network plane reachable by anyone who can send a UDP packet.
func FuzzPeekInitial(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x44, 0x9e})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := PeekInitial(b)
		if err != nil {
			if p.ClientHello != nil {
				t.Fatalf("an error came back with a ClientHello: %x", b)
			}
			return
		}
		if len(p.ClientHello) == 0 {
			t.Fatalf("success with no ClientHello: %x", b)
		}
	})
}
