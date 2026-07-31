package fieldmap_test

import (
	"sort"
	"testing"

	"github.com/lucianoengel/openshield/internal/fieldmap"
)

// SIEM-13 — CROSS-VENDOR FIELD NORMALISATION.
//
// "Which user did this?" is `suser` in CEF, `userIdentityArn` in CloudTrail and `SubjectUserName` in a
// Windows security event. An analyst hunting one user across three sources needs three queries and has
// to remember all three — and a hunt that misses a source does not say so. It returns fewer rows and
// reads as a narrower blast radius, so a gap in coverage looks exactly like good news.

// Realistic field sets, as each ingester actually produces them.
var (
	cefFields = map[string]string{
		"suser": "alice", "duser": "root", "src": "10.1.1.5", "dst": "10.2.2.9",
		"dvchost": "fw-01", "act": "blocked", "outcome": "failure", "fname": "payroll.xlsx",
	}
	cloudTrailFields = map[string]string{
		"eventSource": "s3.amazonaws.com", "eventName": "GetObject", "awsRegion": "us-east-1",
		"sourceIPAddress": "10.1.1.5", "userIdentityArn": "alice", "errorCode": "AccessDenied",
		"recipientAccountId": "123456789012",
	}
	windowsFields = map[string]string{
		"SubjectUserName": "alice", "TargetUserName": "svc_backup", "IpAddress": "10.1.1.5",
		"WorkstationName": "WS-14", "NewProcessName": `C:\Windows\System32\cmd.exe`,
		"ProcessName": `C:\Windows\explorer.exe`, "Status": "0xC000006D",
	}
)

// THE HEADLINE: one canonical name reaches the same fact in three different vocabularies.
func TestOneCanonicalNameReachesEverySource(t *testing.T) {
	for _, tc := range []struct {
		source string
		fields map[string]string
	}{
		{"CEF", cefFields},
		{"CloudTrail", cloudTrailFields},
		{"Windows", windowsFields},
	} {
		got := fieldmap.Canonicalize(tc.fields)
		if got[fieldmap.User] != "alice" {
			t.Errorf("%s: canonical %q = %q, want \"alice\" — an analyst hunting one user across "+
				"sources would have to know this source's own vocabulary, and a hunt that misses a "+
				"source returns fewer rows rather than an error",
				tc.source, fieldmap.User, got[fieldmap.User])
		}
		if got[fieldmap.SourceIP] != "10.1.1.5" {
			t.Errorf("%s: canonical %q = %q, want \"10.1.1.5\"",
				tc.source, fieldmap.SourceIP, got[fieldmap.SourceIP])
		}
	}
}

// PRIORITY ORDER IS LOAD-BEARING WHERE A SOURCE CARRIES TWO CANDIDATES.
//
// A Windows 4688 records both the parent (`ProcessName`) and the process that was created
// (`NewProcessName`). An analyst asking for "the process" means the one that started; picking the parent
// would attribute the execution to explorer.exe on every single event, which is not a missing answer but
// a confidently wrong one.
//
// Mutation (reorder the Process aliases): the parent wins → FAIL.
func TestThePriorityOrderPicksTheProcessThatStarted(t *testing.T) {
	got := fieldmap.Canonicalize(windowsFields)
	if got[fieldmap.Process] != `C:\Windows\System32\cmd.exe` {
		t.Fatalf("canonical process = %q, want the CREATED process — resolving to the parent would "+
			"attribute every execution on the host to explorer.exe", got[fieldmap.Process])
	}
}

// A CANONICAL NAME A SOURCE DOES NOT CARRY IS ABSENT, NOT BLANK.
//
// "This source has no destination IP" and "this event's destination IP was empty" are different facts.
// Collapsing them lets an analyst conclude the map covers a source it does not — the same
// looks-like-good-news failure, one level down.
//
// Mutation (emit every canonical name, empty when unmatched): dest_ip is present → FAIL.
func TestAnUncoveredCanonicalNameIsAbsentRatherThanEmpty(t *testing.T) {
	got := fieldmap.Canonicalize(cloudTrailFields)
	if v, present := got[fieldmap.DestIP]; present {
		t.Fatalf("CloudTrail produced canonical %q = %q; it carries no destination IP, and reporting it "+
			"as blank is indistinguishable from an event that genuinely had none",
			fieldmap.DestIP, v)
	}
	// An empty VALUE in the source is treated the same way, for the same reason.
	got2 := fieldmap.Canonicalize(map[string]string{"suser": "", "src": "10.0.0.1"})
	if v, present := got2[fieldmap.User]; present {
		t.Fatalf("an empty suser produced canonical user = %q, want absent", v)
	}
	if got2[fieldmap.SourceIP] != "10.0.0.1" {
		t.Fatalf("the non-empty field beside it was lost: %v", got2)
	}
}

// MATCHING IS CASE-INSENSITIVE, because the conventions collide: CEF is lower-case, Windows EventData is
// PascalCase, CloudTrail is camelCase. An exact-case map silently misses a vendor that capitalised
// differently from whatever this table was written against.
//
// Mutation (drop the lower-casing): the differently-cased keys stop resolving → FAIL.
func TestMatchingIsCaseInsensitive(t *testing.T) {
	got := fieldmap.Canonicalize(map[string]string{"sUser": "bob", "SRC": "10.9.9.9"})
	if got[fieldmap.User] != "bob" || got[fieldmap.SourceIP] != "10.9.9.9" {
		t.Fatalf("case-variant keys did not resolve: %v — CEF, CloudTrail and Windows each use a "+
			"different convention, so exact-case matching misses whichever one the table was not "+
			"written against", got)
	}
}

// THE VOCABULARY IS CLOSED AND ENUMERABLE, and Aliases hands out a COPY.
//
// A normalisation nobody can enumerate is one an analyst has to learn from the source. And a shared
// slice handed to a caller that sorts or truncates it would silently change every later lookup — the
// priority order above is exactly what that would destroy.
func TestTheVocabularyIsEnumerableAndAliasesAreNotShared(t *testing.T) {
	canon := fieldmap.Canonical()
	if len(canon) == 0 {
		t.Fatal("the canonical vocabulary is empty")
	}
	if !sort.StringsAreSorted(canon) {
		t.Errorf("Canonical() is not sorted: %v — an unstable order makes it useless for display", canon)
	}
	for _, c := range canon {
		if !fieldmap.IsCanonical(c) {
			t.Errorf("%q is listed but not canonical", c)
		}
		if len(fieldmap.Aliases(c)) == 0 {
			t.Errorf("canonical %q maps to no source field — a name in the vocabulary that reaches "+
				"nothing is a promise of coverage that does not exist", c)
		}
	}
	if fieldmap.IsCanonical("suser") {
		t.Error("a source-specific key is being reported as canonical")
	}
	if fieldmap.Aliases("not_a_field") != nil {
		t.Error("a non-canonical name returned aliases")
	}

	// Mutating what Aliases returns must not affect the next caller. Host is the alias set used here
	// because sorting it genuinely moves its first element — on a set whose priority order happens to
	// already be sorted, this assertion would pass against a shared slice and prove nothing.
	first := fieldmap.Aliases(fieldmap.Host)
	before := first[0]
	sort.Strings(first)
	if first[0] == before {
		t.Fatalf("sorting %q's aliases did not move the first element, so this test cannot detect a "+
			"shared slice — pick a set whose priority order is not already sorted", fieldmap.Host)
	}
	if again := fieldmap.Aliases(fieldmap.Host); again[0] != before {
		t.Fatalf("sorting the returned slice changed the shared priority order (now %q, was %q) — the "+
			"parent-vs-created-process resolution above depends on that order surviving", again[0], before)
	}
}

// An empty or nil field set produces nil, not an empty map that reads as "normalised, found nothing".
func TestNoFieldsProducesNoProjection(t *testing.T) {
	if got := fieldmap.Canonicalize(nil); got != nil {
		t.Errorf("Canonicalize(nil) = %v, want nil", got)
	}
	if got := fieldmap.Canonicalize(map[string]string{}); got != nil {
		t.Errorf("Canonicalize(empty) = %v, want nil", got)
	}
	if got := fieldmap.Canonicalize(map[string]string{"nothing_we_map": "x"}); got != nil {
		t.Errorf("Canonicalize(unmapped) = %v, want nil", got)
	}
}
