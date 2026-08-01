package classify

import (
	"strings"
	"testing"
)

// THE ALGORITHMS ARE ANCHORED TO PUBLISHED WORKED EXAMPLES, not to themselves.
//
// A check-digit routine verified only by round-tripping its own output passes against a completely
// wrong table — and the failure surfaces as a national-ID detector that quietly misses real identifiers
// and reports invented ones, in the deployment that trusted it. These are the published values; if this
// code and the published algorithm ever disagree, this fails with their numbers.
func TestTheCheckAlgorithmsMatchTheirPublishedExamples(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		valid bool
	}{
		{"Spain DNI", "12345678Z", true},
		{"Spain NIE (X)", "X1234567L", true},
		{"Spain DNI, wrong letter", "12345678A", false},
		{"Spain NIE, DNI letter for the same digits", "X1234567Z", false},
	} {
		if got := esDNIValid(tc.value); got != tc.valid {
			t.Errorf("%s: esDNIValid(%q) = %v, want %v — this implementation disagrees with the "+
				"published check-letter table", tc.name, tc.value, got, tc.valid)
		}
	}

	// France: the published worked example 2 69 05 49 588 157 80.
	if !frNIRValid("269054958815780") {
		t.Error("frNIRValid rejected the published worked example 2 69 05 49 588 157 80")
	}
	if frNIRValid("269054958815781") {
		t.Error("frNIRValid accepted the published example with its key off by one — the key is not " +
			"being checked, and every 15-digit run in a corpus becomes a reported identifier")
	}
}

// THE NIE LETTER SUBSTITUTION IS LOAD-BEARING.
//
// A NIE replaces its leading letter with a digit (X→0, Y→1, Z→2) before the modulo. Getting it wrong
// makes every NIE fail while every DNI passes — an entire population of identifiers invisible, with
// nothing in the output to suggest it. Each prefix is checked separately because a substitution that
// handled only X would still pass a test that only used X.
func TestEachNIEPrefixIsSubstitutedCorrectly(t *testing.T) {
	for _, valid := range []string{"X1234567L", "Y1234567X", "Z1234567R"} {
		if !esDNIValid(valid) {
			t.Errorf("%s was rejected — the %c prefix is not being substituted with its digit, so every "+
				"NIE beginning %c is invisible", valid, valid[0], valid[0])
		}
	}
	// And the substitution is not a no-op: Y and Z must not accept X's letter.
	if esDNIValid("Y1234567L") || esDNIValid("Z1234567L") {
		t.Error("a NIE accepted the check letter belonging to a different prefix — the leading letter " +
			"is being ignored rather than substituted")
	}
}

// A SPANISH ID IS ONLY REPORTED NEAR CONTEXT, and this is why.
//
// The check is one letter chosen from 23, so roughly one in twenty-three arbitrary "8 digits then a
// letter" tokens passes it — and that shape is everywhere: order numbers, part codes, a hash broken
// across a line. An unguarded detector reports a few percent of them forever, and a detector an
// operator learns to ignore protects nothing.
//
// Mutation (drop the keyword requirement): the bare identifier is reported → FAIL.
func TestASpanishIDIsReportedOnlyNearItsContext(t *testing.T) {
	withContext := []byte("Cliente: DNI 12345678Z, alta el 3 de marzo")
	bare := []byte("reference 12345678Z shipped on the 3rd")

	if n, _ := (esDNI{}).Scan(withContext); n != 1 {
		t.Errorf("a DNI next to the word DNI was not detected (%d hits)", n)
	}
	if n, _ := (esDNI{}).Scan(bare); n != 0 {
		t.Errorf("a bare 8-digit-plus-letter token was reported as a DNI (%d hits). One in every "+
			"twenty-three such tokens passes the check by chance, and that shape is everywhere", n)
	}
}

// A FRENCH NIR STANDS ALONE, because 1-in-97 over a 15-digit shape is strong enough that requiring a
// keyword would only lose real hits.
func TestAFrenchNIRIsDetectedWithoutContext(t *testing.T) {
	if n, _ := (frNIR{}).Scan([]byte("Dossier 2 69 05 49 588 157 80 clos")); n != 1 {
		t.Error("a spaced NIR was not detected — the conventional written form is the one that " +
			"appears in documents")
	}
	if n, _ := (frNIR{}).Scan([]byte("Dossier 269054958815780 clos")); n != 1 {
		t.Errorf("an unspaced NIR was not detected (%d hits)", n)
	}
	// And a 15-digit run that is not a NIR is not reported.
	if n, _ := (frNIR{}).Scan([]byte("order 269054958815781 shipped")); n != 0 {
		t.Errorf("a 15-digit number failing the key check was reported as a NIR (%d hits)", n)
	}
}

// THE COUNT IS OF DISTINCT VALUES, so a repeated identifier does not inflate the evidence a policy acts
// on — the same discipline every other detector here follows.
func TestARepeatedIdentifierIsCountedOnce(t *testing.T) {
	body := strings.Repeat("NIR 269054958815780. ", 5)
	if n, _ := (frNIR{}).Scan([]byte(body)); n != 1 {
		t.Errorf("the same NIR five times counted %d — a repeated value would inflate the count a "+
			"policy thresholds on", n)
	}
}
