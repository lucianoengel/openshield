package attest

import (
	"encoding/asn1"
	"testing"
)

// tcgArc decides whether an OID belongs to the TCG's 2.23.133 arc, and it is used while validating an EK
// certificate — the evidence that a TPM is a real TPM from a known manufacturer.
//
// It is a PREFIX test, which is the correct shape (the arc contains a whole tree: 2.23.133.2.1 is the
// manufacturer attribute, 2.23.133.8.1 the EK certificate policy, and so on). Prefix tests have two
// classic failure modes and they fail in opposite directions:
//
//   - too permissive: comparing only as far as the SHORTER of the two, so the bare `2.23` — or anything —
//     matches, and OIDs from arcs that have nothing to do with the TCG are accepted as TPM evidence.
//   - too strict: demanding exact equality, so every real attribute under the arc is rejected and no EK
//     certificate validates at all.
//
// The table covers both, including the boundary that separates them: an OID SHORTER than the arc must be
// refused, and one exactly equal to it must be accepted.
func TestTCGArcMatchesTheArcAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		name string
		oid  asn1.ObjectIdentifier
		want bool
	}{
		{"the arc itself", asn1.ObjectIdentifier{2, 23, 133}, true},
		{"TPM manufacturer attribute", asn1.ObjectIdentifier{2, 23, 133, 2, 1}, true},
		{"TPM model attribute", asn1.ObjectIdentifier{2, 23, 133, 2, 2}, true},
		{"EK certificate policy", asn1.ObjectIdentifier{2, 23, 133, 8, 1}, true},
		{"deep under the arc", asn1.ObjectIdentifier{2, 23, 133, 8, 1, 4, 7, 9}, true},

		{"one component short", asn1.ObjectIdentifier{2, 23}, false},
		{"two components short", asn1.ObjectIdentifier{2}, false},
		{"empty", asn1.ObjectIdentifier{}, false},
		{"nil", nil, false},

		{"sibling arc", asn1.ObjectIdentifier{2, 23, 134}, false},
		{"sibling arc, deep", asn1.ObjectIdentifier{2, 23, 134, 2, 1}, false},
		{"differs in the middle", asn1.ObjectIdentifier{2, 24, 133}, false},
		{"differs at the root", asn1.ObjectIdentifier{1, 23, 133}, false},
		// 1330 is a DIFFERENT component from 133, not a longer spelling of it. An implementation comparing
		// text rather than components would get this wrong.
		{"numerically similar component", asn1.ObjectIdentifier{2, 23, 1330}, false},
		{"the arc's components out of order", asn1.ObjectIdentifier{133, 23, 2}, false},
		{"a common commercial arc", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcgArc(tc.oid); got != tc.want {
				t.Fatalf("tcgArc(%v) = %v, want %v", tc.oid, got, tc.want)
			}
		})
	}
}
