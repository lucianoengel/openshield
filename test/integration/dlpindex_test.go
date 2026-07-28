//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// EXACT-DATA MATCHING, end to end (D300).
//
// EDM is the DLP capability that distinguishes "a string that looks like an ID" from "THIS customer's
// ID" — the operator seeds an index from their own sensitive values and the classifier fires only on
// those. It is also the capability I nearly re-implemented in D295: three unused constructors and three
// declared settings made it look unreachable, and the worker in fact loads all three index kinds through
// a different call. Checking beat guessing — and this scenario is what turns that check into something
// that stays true.
//
// It drives the WHOLE operator loop with the shipped binaries: `openshield-dlp-index` builds and SIGNS an
// index from a values file, the engine's worker verifies and loads it, and a file containing a seeded
// value is detected while a file of similar-looking-but-unseeded values is not.

const edmPolicy = `package openshield
import rego.v1
edm_hit if { some h in input.classification; h.type == "DETECTOR_TYPE_EDM" }
decision := {"action":"ALERT","reason":"exact data match"} if { edm_hit }
decision := {"action":"ALLOW","reason":"no exact match"} if { not edm_hit }`

func TestASignedEDMIndexIsBuiltSignedAndUsedByTheEngine(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	watch := t.TempDir()

	// 1. The operator mints a key and builds a SIGNED index from their own sensitive values.
	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "op.key"), "--out-pub", filepath.Join(work, "op.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	values := filepath.Join(work, "values.txt")
	// Values that are NOT detectable by any built-in detector, so a hit can only come from the index.
	// Seeding a CPF would make the test pass on the built-in CPF detector and prove nothing about EDM.
	if err := os.WriteFile(values, []byte("ZX-8842-QQ\nMM-7731-VV\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "edm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "edm", "--in", values, "--key", filepath.Join(work, "op.key"), "--out", index); err != nil {
		t.Fatalf("building the index: %v\n%s", err, out)
	}

	policy := filepath.Join(work, "edm.rego")
	if err := os.WriteFile(policy, []byte(edmPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. The engine's worker VERIFIES and loads it. Without the public key the worker would take the
	// legacy unsigned path — configuring both is what proves the signed path runs.
	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_EDM_INDEX=" + index,
		"OPENSHIELD_DLP_INDEX_PUBKEY=" + filepath.Join(work, "op.pub"),
	})
	eng.WaitForOutput("engine observing", 90*time.Second)

	pool := openPool(t, stack.DSN)
	alerts := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// 3. A file with a NON-seeded value of the same shape must NOT alert. This is the half that makes
	// the test about EXACT matching rather than about the pipeline running: a classifier that fired on
	// everything would pass a seeded-value-only test.
	if err := os.WriteFile(filepath.Join(watch, "unseeded.txt"), []byte("ref: AB-1234-CD\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("a value that is NOT in the index produced %d alert(s) — EDM's whole claim is that it "+
			"fires on the operator's OWN data, not on anything of a similar shape\n%s", n, eng.Output())
	}

	// 4. A file containing a SEEDED value alerts.
	if err := os.WriteFile(filepath.Join(watch, "seeded.txt"), []byte("customer ref ZX-8842-QQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 120*time.Second, "the seeded value to be detected by the signed EDM index", func() bool {
		return alerts() > 0
	})

	// 5. The RAW VALUE is not in the index file. The index ships to endpoints; if it carried the
	// sensitive values it was built from, distributing detection would be distributing the data.
	blob, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(blob), "ZX-8842-QQ") {
		t.Error("the built index CONTAINS a raw seeded value — the index is k-anonymised hashes precisely " +
			"so it can be shipped into the sandbox and across a fleet without shipping the data")
	}
}

// mintIndexKey creates an operator signing keypair and returns both paths.
func mintIndexKey(t *testing.T, dir string) (key, pub string) {
	t.Helper()
	key, pub = filepath.Join(dir, "op.key"), filepath.Join(dir, "op.pub")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen", "--out-key", key, "--out-pub", pub); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	return key, pub
}

// startIndexEngine runs the engine over a watch directory with a policy and index settings, and
// returns the watch directory plus a counter of ALERT audit rows.
func startIndexEngine(t *testing.T, stack *Stack, work, policyText string, extra ...string) (watch string, alerts func() int) {
	t.Helper()
	watch = t.TempDir()
	policy := filepath.Join(work, "index.rego")
	if err := os.WriteFile(policy, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := Start(t, "openshield-engine", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
	}, extra...))
	eng.WaitForOutput("engine observing", 90*time.Second)

	pool := openPool(t, stack.DSN)
	return watch, func() int {
		var n int
		if err := pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries WHERE action = 2`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
}

// MULTI-CELL EDM (OPENSHIELD_EDM_RECORD_INDEX).
//
// Single-value EDM fires on one indexed value. A record index requires a THRESHOLD of distinct cells
// OF THE SAME RECORD to co-occur — which is the whole reason it exists: coincidentally matching two
// specific fields of one customer's row is astronomically less likely than matching one field, so the
// false-positive rate drops far enough to act on.
//
// THE NEGATIVE IS THE TEST. A file holding one cell from record A and one cell from record B contains
// two indexed values and still must not fire, because those two facts were never true together. An
// implementation that counted indexed cells instead of tracking WHICH record each belongs to would
// pass every positive case and fail only here — and it would fail in production as a stream of alerts
// on documents that merely mention two customers.
func TestARecordIndexRequiresCellsOfTheSameRecord(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	_, pub := mintIndexKey(t, work)

	// Two records, two distinctive cells each. Values no built-in detector recognises, so a hit can
	// only have come from the index.
	records := filepath.Join(work, "records.tsv")
	if err := os.WriteFile(records, []byte("ZX-8842-QQ\tMM-7731-VV\nAB-9911-KK\tCD-4422-LL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "record.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "record", "--in", records, "--key", filepath.Join(work, "op.key"), "--out", index); err != nil {
		t.Fatalf("building the record index: %v\n%s", err, out)
	}

	watch, alerts := startIndexEngine(t, stack, work, edmPolicy,
		"OPENSHIELD_EDM_RECORD_INDEX="+index,
		"OPENSHIELD_DLP_INDEX_PUBKEY="+pub)

	// ONE cell of a record: below the threshold, so no match.
	if err := os.WriteFile(filepath.Join(watch, "single-cell.txt"),
		[]byte("customer reference ZX-8842-QQ was updated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cells from DIFFERENT records: two indexed values, no record.
	if err := os.WriteFile(filepath.Join(watch, "cross-record.txt"),
		[]byte("tickets ZX-8842-QQ and CD-4422-LL were merged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("%d alert(s) fired on content holding no COMPLETE record — one cell, or cells of two "+
			"different records. Multi-cell EDM's entire claim is that several fields of the SAME record "+
			"co-occur; counting indexed cells instead makes it single-value EDM with a slower index", n)
	}

	// Both cells of ONE record.
	if err := os.WriteFile(filepath.Join(watch, "whole-record.txt"),
		[]byte("export row: ZX-8842-QQ, MM-7731-VV\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 120*time.Second, "two cells of the SAME record to be detected", func() bool {
		return alerts() > 0
	})
}

// DOCUMENT MATCHING (OPENSHIELD_IDM_INDEX).
//
// IDM fingerprints a sensitive DOCUMENT as overlapping word shingles, so it survives excerpting and
// reformatting — the ways a document actually leaves, pasted into an email with the line breaks and
// casing mangled, rather than attached whole.
//
// Its risk is the mirror image of EDM's: fire on a single shingle and every document quoting one
// sentence of a memo becomes an incident. So the negative here is a SHORT QUOTE from the very same
// document — indexed content, deliberately below the fraction threshold. That is the guard an
// implementation loses by treating any shingle hit as a match, and losing it is invisible until the
// alert queue fills with people discussing the memo rather than leaking it.
func TestADocumentIndexMatchesAReformattedExcerptButNotAQuote(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	_, pub := mintIndexKey(t, work)

	docs := filepath.Join(work, "docs")
	if err := os.MkdirAll(docs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "board-memo.txt"), []byte(sensitiveMemo), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "idm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "idm", "--in", docs, "--key", filepath.Join(work, "op.key"), "--out", index); err != nil {
		t.Fatalf("building the document index: %v\n%s", err, out)
	}

	watch, alerts := startIndexEngine(t, stack, work, idmPolicy,
		"OPENSHIELD_IDM_INDEX="+index,
		"OPENSHIELD_DLP_INDEX_PUBKEY="+pub)

	// A passing mention — one clause of the memo inside an ordinary message. It OVERLAPS the indexed
	// document: 3 of the document's 57 shingles, against a threshold of 18. That measurement is what
	// makes this a test of the FRACTION guard rather than of "unrelated text does not match"; rewriting
	// the quote into something the memo does not contain would quietly turn it into the latter.
	if err := os.WriteFile(filepath.Join(watch, "quote.txt"), []byte(
		"Quick question before standup: diligence has surfaced an unrecorded pension liability, "+
			"is that the thing legal wanted a note on? Nothing urgent.\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if n := alerts(); n != 0 {
		t.Fatalf("%d alert(s) fired on a one-clause QUOTE of the indexed document. IDM must fire on a "+
			"substantial FRACTION of a document; a single-shingle match makes every conversation about a "+
			"memo indistinguishable from the memo leaving", n)
	}

	// A real excerpt, REFORMATTED — lowercased, re-wrapped, punctuation changed, pasted into an email.
	// Shingles are normalized precisely so this still matches; a byte-comparison never would.
	if err := os.WriteFile(filepath.Join(watch, "pasted-into-email.txt"), []byte(memoExcerpt), 0o600); err != nil {
		t.Fatal(err)
	}
	Eventually(t, 120*time.Second, "a reformatted excerpt of the indexed document to be detected", func() bool {
		return alerts() > 0
	})

	// And the document's TEXT is not in the index — the same ADR-9 property the EDM index has, and the
	// one that lets an index of the company's most sensitive documents ship to every endpoint.
	blob, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(blob), "Harbourline") || contains(string(blob), "pension") {
		t.Error("the document index CONTAINS words from the indexed document — an IDM index is shingle " +
			"HASHES so that distributing detection is not distributing the documents")
	}
}

const idmPolicy = `package openshield
import rego.v1
idm_hit if { some h in input.classification; h.type == "DETECTOR_TYPE_IDM" }
decision := {"action":"ALERT","reason":"document match"} if { idm_hit }
decision := {"action":"ALLOW","reason":"no document match"} if { not idm_hit }`

// sensitiveMemo is the fingerprinted document. It is prose rather than structured data because that
// is what IDM is for — the material EDM cannot see, where there is no field to index.
const sensitiveMemo = `Project Nightjar contemplates the acquisition of Harbourline Logistics for four
hundred and twelve million reais, funded by a bridge facility from Banco Meridiano. The board has not
yet been informed. Diligence has surfaced an unrecorded pension liability in the Rotterdam subsidiary
which the sellers dispute. Completion is targeted for the second quarter, conditional on regulatory
clearance in Brazil and the Netherlands.`

// memoExcerpt is a substantial run of the memo after a trip through a mail client: lowercased,
// re-wrapped, punctuation replaced, and surrounded by unrelated text.
const memoExcerpt = `hi — pasting the relevant bit below so you do not have to open the deck

the board has not yet been informed diligence has surfaced an unrecorded pension liability in the
rotterdam subsidiary which the sellers dispute completion is targeted for the second quarter

let me know if legal needs anything else from me today
`

// TestATamperedEDMIndexIsRefused is the signature half (ADR-9).
//
// A poisoned or swapped index can silently DISABLE exfil detection — the quiet failure, since a detector
// that finds nothing looks exactly like an endpoint with nothing to find.
func TestATamperedEDMIndexIsRefused(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen",
		"--out-key", filepath.Join(work, "op.key"), "--out-pub", filepath.Join(work, "op.pub")); err != nil {
		t.Fatalf("keygen: %v\n%s", err, out)
	}
	values := filepath.Join(work, "values.txt")
	if err := os.WriteFile(values, []byte("ZX-8842-QQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "edm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "edm", "--in", values, "--key", filepath.Join(work, "op.key"), "--out", index); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}
	blob, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle — the shape of a poisoned index in transit.
	blob[len(blob)/2] ^= 0xFF
	if err := os.WriteFile(index, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	// The worker ABORTS on a bad index rather than starting without it: silently classifying with no
	// index would leave an operator believing EDM is on.
	out := refuseToStart(t, "openshield-worker", []string{
		"OPENSHIELD_EDM_INDEX=" + index,
		"OPENSHIELD_DLP_INDEX_PUBKEY=" + filepath.Join(work, "op.pub"),
	})
	// The refusal must name the VERIFICATION, not merely fail. A tampered blob also fails to PARSE, so
	// "the worker exited" cannot tell a signature check from a decoder giving up — and a build with the
	// signature check removed still exits, which is exactly what an earlier version of this assertion
	// accepted.
	if !contains(out, "refusing to load an unverified index") {
		t.Errorf("the refusal does not name the signature check, so it is indistinguishable from a parse "+
			"failure:\n%s", out)
	}
}

// TestAnEDMIndexSignedByTheWrongKeyIsRefused isolates the SIGNATURE from parseability.
//
// A tampered index is both unverifiable and unparseable, so refusing it proves little on its own. This
// one is perfectly well-formed and correctly signed — by the wrong operator. Only the signature check
// can reject it, which is the property ADR-9 is for: a swapped index from a compromised distribution
// path silently disabling exfil detection.
func TestAnEDMIndexSignedByTheWrongKeyIsRefused(t *testing.T) {
	work := t.TempDir()
	mint := func(prefix string) (key, pub string) {
		t.Helper()
		key, pub = filepath.Join(work, prefix+".key"), filepath.Join(work, prefix+".pub")
		if out, err := runCapture(t, "openshield-dlp-index", nil, "keygen", "--out-key", key, "--out-pub", pub); err != nil {
			t.Fatalf("keygen: %v\n%s", err, out)
		}
		return key, pub
	}
	attackerKey, _ := mint("attacker")
	_, operatorPub := mint("operator")

	values := filepath.Join(work, "values.txt")
	if err := os.WriteFile(values, []byte("ZX-8842-QQ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(work, "edm.index")
	if out, err := runCapture(t, "openshield-dlp-index", nil, "build",
		"--type", "edm", "--in", values, "--key", attackerKey, "--out", index); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}

	out := refuseToStart(t, "openshield-worker", []string{
		"OPENSHIELD_EDM_INDEX=" + index,
		"OPENSHIELD_DLP_INDEX_PUBKEY=" + operatorPub,
	})
	if !contains(out, "refusing to load an unverified index") {
		t.Errorf("the refusal does not name the signature check:\n%s", out)
	}
}
