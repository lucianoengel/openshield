package attest

import (
	"bytes"
	"testing"
)

func TestEnrollmentJSONRoundTrip(t *testing.T) {
	// A syntactically-valid AK public blob is not needed for the encoding
	// round-trip — Marshal/Parse only (de)code, they do not Validate.
	records := []AttestationEnrollment{
		{Subject: "sub_b", AKPublic: []byte{0x01, 0x02, 0x03}, Golden: map[int][]byte{16: {0xaa}, 23: {0xbb, 0xcc}}},
		{Subject: "sub_a", AKPublic: []byte{0x09}, Golden: map[int][]byte{0: {0x00}}},
	}
	data, err := MarshalEnrollments(records)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := ParseEnrollments(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	// Marshal sorts by subject; find each and compare.
	byName := map[string]AttestationEnrollment{}
	for _, r := range got {
		byName[r.Subject] = r
	}
	for _, want := range records {
		g, ok := byName[want.Subject]
		if !ok {
			t.Fatalf("missing %q after round-trip", want.Subject)
		}
		if !bytes.Equal(g.AKPublic, want.AKPublic) {
			t.Errorf("%q AK: got %x want %x", want.Subject, g.AKPublic, want.AKPublic)
		}
		for idx, v := range want.Golden {
			if !bytes.Equal(g.Golden[idx], v) {
				t.Errorf("%q PCR %d: got %x want %x", want.Subject, idx, g.Golden[idx], v)
			}
		}
	}
}

func TestEnrollmentValidateRejectsIncomplete(t *testing.T) {
	// Empty subject.
	if err := (AttestationEnrollment{AKPublic: []byte{1}, Golden: map[int][]byte{0: {1}}}).Validate(); err == nil {
		t.Error("empty subject should fail Validate")
	}
	// Unparseable AK bytes (not a TPM2BPublic).
	if err := (AttestationEnrollment{Subject: "s", AKPublic: []byte{0xff, 0xff}, Golden: map[int][]byte{0: {1}}}).Validate(); err == nil {
		t.Error("bad AK bytes should fail Validate")
	}
	// Empty baseline.
	if err := (AttestationEnrollment{Subject: "s", AKPublic: []byte{1}, Golden: map[int][]byte{}}).Validate(); err == nil {
		t.Error("empty baseline should fail Validate")
	}
}
