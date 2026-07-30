package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lucianoengel/openshield/internal/attest"
)

func enrollment(subject string) attest.AttestationEnrollment {
	return attest.AttestationEnrollment{
		Subject:  subject,
		AKPublic: []byte("ak-" + subject),
		Golden:   map[int][]byte{0: []byte("pcr0-" + subject), 7: []byte("pcr7-" + subject)},
	}
}

func writeEnrollments(t *testing.T, path string, records ...attest.AttestationEnrollment) {
	t.Helper()
	blob, err := attest.MarshalEnrollments(records)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatal(err)
	}
}

func subjectsOf(records []attest.AttestationEnrollment) map[string]int {
	seen := map[string]int{}
	for _, r := range records {
		seen[r.Subject]++
	}
	return seen
}

// "MERGES — capturing one device never unenrolls the others" is the command's documented promise, and a
// fleet is enrolled one machine at a time, so this runs on every capture after the first.
//
// The failure it prevents is quiet in the worst way: an unenrolled device's attestation is not APPLIED, so
// truncating this file does not break anything visibly. It removes the evidence requirement from every
// other machine, and the symptom is that attestation stops mattering — which looks exactly like
// attestation passing.
func TestCapturingOneDeviceKeepsEveryOtherEnrollment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	writeEnrollments(t, path, enrollment("laptop-01"), enrollment("laptop-02"), enrollment("server-01"))

	got := mergeEnrollments(path, enrollment("laptop-03"))

	seen := subjectsOf(got)
	for _, want := range []string{"laptop-01", "laptop-02", "server-01", "laptop-03"} {
		if seen[want] != 1 {
			t.Fatalf("subject %q appears %d times after capturing laptop-03; all four must be present "+
				"exactly once: %v", want, seen[want], seen)
		}
	}
	if len(got) != 4 {
		t.Fatalf("got %d records, want 4: %v", len(got), seen)
	}
	// The new record is first, so a human reading the file sees what they just captured.
	if got[0].Subject != "laptop-03" {
		t.Fatalf("the newly captured device is not first: %q", got[0].Subject)
	}
}

// Re-capturing a device REPLACES its record. Two records for one subject would leave the gateway resolving
// whichever the loader saw last — a re-enrolment that half worked, which is worse than one that failed.
func TestRecapturingADeviceReplacesItRatherThanDuplicating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollments.json")
	old := enrollment("laptop-01")
	old.AKPublic = []byte("the-OLD-ak")
	writeEnrollments(t, path, old, enrollment("laptop-02"))

	got := mergeEnrollments(path, enrollment("laptop-01"))

	if seen := subjectsOf(got); seen["laptop-01"] != 1 {
		t.Fatalf("laptop-01 appears %d times after re-capture: %v", seen["laptop-01"], seen)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	for _, r := range got {
		if r.Subject == "laptop-01" && string(r.AKPublic) == "the-OLD-ak" {
			t.Fatal("the OLD attestation key survived the re-capture — the device was re-enrolled with " +
				"the key it was supposed to be rotating away from")
		}
	}
	if seen := subjectsOf(got); seen["laptop-02"] != 1 {
		t.Fatal("laptop-02 was lost during laptop-01's re-capture")
	}
}

func TestTheFirstCaptureNeedsNoExistingFile(t *testing.T) {
	got := mergeEnrollments(filepath.Join(t.TempDir(), "absent.json"), enrollment("laptop-01"))
	if len(got) != 1 || got[0].Subject != "laptop-01" {
		t.Fatalf("first capture produced %d records: %v", len(got), subjectsOf(got))
	}
}

func TestParsePCRList(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []int
	}{
		{"the common baseline", "0,7", []int{0, 7}},
		{"single", "7", []int{7}},
		{"whitespace around each", " 0 , 7 , 14 ", []int{0, 7, 14}},
		{"empty fields are skipped", "0,,7", []int{0, 7}},
		{"order is preserved, not sorted", "7,0", []int{7, 0}},
		{"duplicates are kept as given", "0,0", []int{0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePCRList(tc.in)
			if err != nil {
				t.Fatalf("parsePCRList(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parsePCRList(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("parsePCRList(%q) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// AN EMPTY BASELINE ATTESTS TO NOTHING. Accepting one would enroll a device whose golden PCR set is empty,
// and "no PCRs to compare" is indistinguishable from "every PCR matched" unless something refuses it here.
func TestParsePCRListRefusesAnEmptyOrMalformedBaseline(t *testing.T) {
	for _, in := range []string{"", " ", ",", ",,,", " , , "} {
		t.Run("empty:"+in, func(t *testing.T) {
			if got, err := parsePCRList(in); err == nil {
				t.Fatalf("parsePCRList(%q) = %v with no error — an empty baseline was accepted", in, got)
			}
		})
	}
	// A trailing comma is NOT in this list: it is a skipped empty field and parses fine ("0,7," -> [0,7]).
	// It was here in the first draft, guarded by a t.Skip, which is a test admitting it does not know what
	// it is asserting.
	for _, in := range []string{"a", "0,seven", "0x7", "7.0", "--pcrs", "0 7"} {
		t.Run("malformed:"+in, func(t *testing.T) {
			if got, err := parsePCRList(in); err == nil {
				t.Fatalf("parsePCRList(%q) = %v with no error", in, got)
			}
		})
	}
}
