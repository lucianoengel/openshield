package quicpeek

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// THE KEY SCHEDULE IS ANCHORED TO RFC 9001, NOT TO ITSELF.
//
// Everything this package does rests on deriving the same Initial keys an endpoint derives. A round-trip
// test — encrypt with my derivation, decrypt with my derivation — would pass against a completely wrong
// schedule, and the failure would only appear against real traffic, as "QUIC never decrypts" with no
// indication why.
//
// So these are the published worked examples from RFC 9001 Appendix A. If this package and the RFC ever
// disagree, these fail, and they fail with the spec's own numbers.

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad fixture hex: %v", err)
	}
	return b
}

// RFC 9001 A.1: the client Initial keys for DCID 0x8394c8f03e515708.
func TestClientInitialKeysMatchRFC9001(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	key, iv, hp, err := clientInitialKeys(saltV1, dcid, Version1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"key", key, "1f369613dd76d5467730efcbe3b1a22d"},
		{"iv", iv, "fa044b2f42a3fd3b46fb255c"},
		{"hp", hp, "9f50449e04a0e810283a1e9933adedd2"},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Errorf("%s = %s, want the RFC 9001 A.1 value %s — a derivation that disagrees with the "+
				"spec decrypts nothing, and the symptom is 'QUIC never works' with no indication why",
				tc.name, got, tc.want)
		}
	}
}

// RFC 9001 A.2: the header-protection sample and the mask it produces.
//
// Worth its own vector because header protection is the step most easily got subtly wrong — the sample
// offset is fixed at four bytes past the packet number precisely so a reader can find it WITHOUT knowing
// the packet-number length it is trying to recover, and an implementation that "helpfully" used the real
// length would work on one-byte packet numbers and silently fail on the rest.
func TestHeaderProtectionMaskMatchesRFC9001(t *testing.T) {
	hp := mustHex(t, "9f50449e04a0e810283a1e9933adedd2")
	sample := mustHex(t, "d1b1c98dd7689fb8ec11d242b123dc9b")
	mask, err := headerMask(hp, sample)
	if err != nil {
		t.Fatal(err)
	}
	const want = "437b9aec36"
	if got := hex.EncodeToString(mask[:5]); got != want {
		t.Fatalf("mask = %s, want the RFC 9001 A.2 value %s", got, want)
	}
}

// The initial secret itself, also from A.1 — so a failure points at extract or at expand rather than
// leaving both suspect.
func TestInitialSecretMatchesRFC9001(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	got := hex.EncodeToString(hkdfExtract(saltV1, dcid))
	const want = "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
	if got != want {
		t.Fatalf("initial_secret = %s, want %s", got, want)
	}
	client := hkdfExpandLabel(hkdfExtract(saltV1, dcid), "client in", 32)
	const wantClient = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
	if got := hex.EncodeToString(client); got != wantClient {
		t.Fatalf("client_initial_secret = %s, want %s", got, wantClient)
	}
}

// VERSION 2 CHANGED BOTH THE SALT AND THE HKDF LABELS, and each is exercised SEPARATELY.
//
// The obvious test — derive v1 with its salt and v2 with its salt, assert the keys differ — passes
// against an implementation that ignores the labels entirely, because the salts alone guarantee
// different output. It would have let a build that derived v2 keys with v1's labels through, and the
// symptom is an entire protocol version reported as "not QUIC" with no other signal. It is written this
// way because the first version of it did exactly that.
//
// STATED HONESTLY: this pins the label path by construction rather than against a published vector. RFC
// 9369 has one, and anchoring to it would be stronger; that is a follow-up rather than a claim made here.
func TestVersion2UsesItsOwnSaltAndItsOwnLabels(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")

	// SAME SALT, different version — so ONLY the labels can account for a difference.
	kSameSalt1, ivSameSalt1, hpSameSalt1, err := clientInitialKeys(saltV2, dcid, Version1)
	if err != nil {
		t.Fatal(err)
	}
	kSameSalt2, ivSameSalt2, hpSameSalt2, err := clientInitialKeys(saltV2, dcid, Version2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(kSameSalt1, kSameSalt2) || bytes.Equal(ivSameSalt1, ivSameSalt2) ||
		bytes.Equal(hpSameSalt1, hpSameSalt2) {
		t.Fatal("with the SAME salt, version 1 and version 2 derived identical keys — the HKDF labels " +
			"are being ignored, and a v2 packet would decrypt to nothing and be reported as 'not QUIC', " +
			"hiding an entire protocol version from the gateway")
	}

	// And the salts differ too, so neither half is carrying the other.
	if bytes.Equal(saltV1, saltV2) {
		t.Fatal("the two version salts are identical")
	}
}

// An unknown version is reported AS a version problem, not as "not QUIC".
//
// A gateway that reported an unrecognised QUIC version as ordinary UDP would let a client reach a
// destination unexamined by negotiating a version this build predates, with no signal at all.
func TestAnUnknownVersionIsDistinctFromNotQUIC(t *testing.T) {
	if _, err := saltFor(0xdeadbeef); err != ErrUnknownVersion {
		t.Fatalf("an unknown version gave %v, want ErrUnknownVersion", err)
	}
	// And the cheap classifier still calls it QUIC, which is the cue for the caller to treat it as
	// QUIC rather than as unclassified UDP.
	pkt := append([]byte{0xc0}, mustHex(t, "deadbeef")...)
	pkt = append(pkt, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00)
	if !IsQUICInitial(pkt) {
		t.Fatal("a QUIC packet with an unknown version was classified as not QUIC — a client could " +
			"reach a destination unexamined by negotiating a version this build predates")
	}
}
