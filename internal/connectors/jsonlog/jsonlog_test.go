package jsonlog_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/connectors/jsonlog"
)

// SIEM-15 — GENERIC JSON-LINES INGEST.
//
// CEF, CloudTrail and WEF each cover one vendor's idea of a log. JSON lines is what everything ELSE
// emits: application logs, Kubernetes, GCP audit, Azure activity, and every shipper's default output.
// This is not "one more format" — it is the difference between a SIEM that ingests three products and
// one that ingests an estate.

var ingestedAt = time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

// THE HEADLINE: a nested document becomes a flat, huntable field set.
//
// Mutation (stop recursing into nested objects): `userIdentity.arn` is absent and the document is
// searchable only by its top-level keys → FAIL.
func TestANestedDocumentFlattensIntoHuntableFields(t *testing.T) {
	const line = `{"@timestamp":"2026-07-30T09:15:00Z","service":{"name":"checkout"},
	  "userIdentity":{"arn":"alice","session":{"mfa":true}},
	  "src":{"ip":"10.1.1.5","port":44321},"tags":["prod","eu"],"message":"payment refused"}`

	rec, err := jsonlog.Parse(line, ingestedAt)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	want := map[string]string{
		"userIdentity.arn":         "alice",
		"userIdentity.session.mfa": "true",
		"src.ip":                   "10.1.1.5",
		"src.port":                 "44321",
		"service.name":             "checkout",
		"tags.0":                   "prod",
		"tags.1":                   "eu",
	}
	for k, v := range want {
		if rec.Fields[k] != v {
			t.Errorf("field %q = %q, want %q — a document searchable only by its top-level keys is "+
				"stored, not ingested", k, rec.Fields[k], v)
		}
	}

	// A NUMBER RENDERS AS A NUMBER. json.Unmarshal makes every number a float64, and an event id
	// stored as "44321.000000" does not match the one an analyst pastes from a report.
	if strings.Contains(rec.Fields["src.port"], ".") {
		t.Errorf("an integer was stored as %q — an id an analyst pastes from a report would never "+
			"match it", rec.Fields["src.port"])
	}

	// The shared columns are filled from what the document actually named.
	if rec.Product != "checkout" || rec.Message != "payment refused" {
		t.Errorf("columns not filled: product=%q message=%q", rec.Product, rec.Message)
	}
	if rec.At.IsZero() || rec.TimeSynthetic {
		t.Errorf("the document carried @timestamp and it was not used (at=%v synthetic=%v)",
			rec.At, rec.TimeSynthetic)
	}
	if !rec.At.Equal(time.Date(2026, 7, 30, 9, 15, 0, 0, time.UTC)) {
		t.Errorf("timestamp = %v, want the document's own", rec.At)
	}
}

// AN INVENTED TIMESTAMP IS DECLARED AS ONE.
//
// A JSON log has no agreed time field. When none is present the ingest time has to stand in — and an
// event whose time was invented sits in the WRONG PLACE on every timeline, so a hunt bounded by time
// misses it while reporting a clean result. The record says which happened; nothing downstream has to
// guess.
//
// Mutation (drop TimeSynthetic, or set it false unconditionally): the two cases become
// indistinguishable → FAIL.
func TestASynthesisedTimestampIsDeclared(t *testing.T) {
	withTime, err := jsonlog.Parse(`{"timestamp":"2026-07-30T09:15:00Z","a":"1"}`, ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if withTime.TimeSynthetic {
		t.Error("a document with its own timestamp was reported as synthetic")
	}

	without, err := jsonlog.Parse(`{"a":"1"}`, ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !without.TimeSynthetic {
		t.Fatal("a document with NO time field was given the ingest time and reported it as the " +
			"event's own — the event then sits in the wrong place on every timeline, and a hunt " +
			"bounded by time misses it while reporting a clean result")
	}
	if !without.At.Equal(ingestedAt) {
		t.Errorf("the fallback time = %v, want the supplied ingest time", without.At)
	}
}

// A DURATION IS NOT A TIMESTAMP.
//
// Matching any key containing "time" would pull in `processing_time_ms`, and a duration parsed as a date
// puts the event in 1970 — not a missing timestamp but a confidently wrong one, which sorts to the top
// of every descending query.
//
// Mutation (match keys by substring instead of the closed list): processing_time_ms is read as the
// event time → FAIL.
func TestADurationFieldIsNotMistakenForTheTimestamp(t *testing.T) {
	// The values are LARGE on purpose. A small duration is rejected by the epoch magnitude bound
	// whatever the key matching does, so a test using `37` would pass against a parser that matched
	// keys by substring — it would be the bound doing the work, and the closed list could be deleted
	// without the test noticing. `uptime_time_ns` and a nanosecond duration are both ordinary fields
	// and both land squarely inside the epoch range.
	rec, err := jsonlog.Parse(
		`{"processing_time_ns":1785500000123,"uptime_time_seconds":1785500000,"a":"1"}`, ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.TimeSynthetic {
		t.Fatalf("a duration field was read as the event's timestamp (at=%v) — that is not a missing "+
			"timestamp but a confidently wrong one, and it sorts to the top of every descending query",
			rec.At)
	}
	if !rec.At.Equal(ingestedAt) {
		t.Fatalf("the fallback time = %v, want the supplied ingest time", rec.At)
	}
}

// EPOCH TIMES ARE UNDERSTOOD, in seconds and milliseconds, because shippers emit them as often as they
// emit RFC 3339 — and a source whose timestamps are all synthetic is a source with no usable timeline.
func TestEpochTimestampsAreUnderstood(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  string
		want time.Time
	}{
		{"seconds", "1785500000", time.Unix(1785500000, 0).UTC()},
		{"milliseconds", "1785500000000", time.UnixMilli(1785500000000).UTC()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := jsonlog.Parse(fmt.Sprintf(`{"ts":%s,"a":"1"}`, tc.val), ingestedAt)
			if err != nil {
				t.Fatal(err)
			}
			if rec.TimeSynthetic || !rec.At.Equal(tc.want) {
				t.Fatalf("epoch %s parsed as %v (synthetic=%v), want %v", tc.name, rec.At,
					rec.TimeSynthetic, tc.want)
			}
		})
	}
}

// AN ARRAY BECOMES INDEXED KEYS, NOT A JOINED STRING.
//
// Joining loses the boundary between elements, so a hunt for an exact value matches a substring spanning
// two adjacent ones — a false positive an analyst has no way to see in the result.
//
// Mutation (join array elements with a separator): searching for the exact value "prod-eu" matches a
// document whose tags were ["prod","eu"] → FAIL.
func TestArrayElementsKeepTheirBoundaries(t *testing.T) {
	rec, err := jsonlog.Parse(`{"tags":["prod","eu"],"a":"1"}`, ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rec.Fields {
		if v == "prod-eu" || v == "prod,eu" || v == "prod eu" {
			t.Fatalf("array elements were joined into %q — an exact-match hunt then matches a "+
				"substring spanning two elements, and the analyst cannot see that in the result", v)
		}
	}
	if rec.Fields["tags.0"] != "prod" || rec.Fields["tags.1"] != "eu" {
		t.Fatalf("array elements did not become indexed keys: %v", rec.Fields)
	}
}

// A NULL IS ABSENT, NOT EMPTY.
//
// The cross-vendor projection (SIEM-13) treats an empty value as "this source does not carry the field".
// Storing a null as "" would make a source that explicitly reported no user indistinguishable from one
// that never has the field — the same absent-versus-blank confusion, one layer down.
func TestANullFieldIsAbsentRatherThanEmpty(t *testing.T) {
	rec, err := jsonlog.Parse(`{"user":null,"host":"ws-1"}`, ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := rec.Fields["user"]; present {
		t.Fatalf("a null was stored as a present field (%q) — an explicit null and a field the source "+
			"does not have are different facts", rec.Fields["user"])
	}
	if rec.Fields["host"] != "ws-1" {
		t.Fatal("the field beside the null was lost")
	}
}

// A DOCUMENT THAT IS NOT AN OBJECT IS REFUSED, and so is unparseable input — reported, never stored as
// an empty row that reports success over something nothing can ever match.
func TestNonObjectsAndGarbageAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"array", `["a","b"]`},
		{"scalar", `"just a string"`},
		{"number", `42`},
		{"empty object", `{}`},
		{"truncated", `{"a":`},
		{"empty line", `   `},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jsonlog.Parse(tc.in, ingestedAt); err == nil {
				t.Fatalf("accepted %q — it would be stored as a row with no fields, which reports "+
					"success over something nothing can ever match", tc.in)
			}
		})
	}
}

// LIMITS ARE ENFORCED AND ANNOUNCED.
//
// This parses whatever an estate sends, so an unbounded document makes the ingest path a denial of
// service anyone able to write a log file can reach. A partial parse that looked complete would be
// worse: a hunt over the missing keys returns nothing and reads as a finding of absence.
//
// Mutation (drop the Truncated flag): an over-wide document parses silently and reads as complete → FAIL.
func TestAnOverWideDocumentIsBoundedAndSaysSo(t *testing.T) {
	doc := map[string]any{}
	for i := 0; i < jsonlog.MaxFields*2; i++ {
		doc[fmt.Sprintf("k%04d", i)] = "v"
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := jsonlog.Parse(string(b), ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Fields) > jsonlog.MaxFields {
		t.Fatalf("the flattened document holds %d fields, over the %d cap", len(rec.Fields), jsonlog.MaxFields)
	}
	if !rec.Truncated {
		t.Fatal("a document that lost fields to the cap did not report itself truncated — a hunt over " +
			"the missing keys returns nothing and reads as a finding of absence")
	}

	// A long VALUE is truncated rather than stored whole: a field this long is not a field, it is a
	// payload.
	long, err := jsonlog.Parse(fmt.Sprintf(`{"a":%q}`, strings.Repeat("x", jsonlog.MaxValueBytes*2)), ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(long.Fields["a"]) > jsonlog.MaxValueBytes {
		t.Fatalf("a value of %d bytes was stored whole", len(long.Fields["a"]))
	}
}

// DEEP NESTING IS BOUNDED, and the branch below the bound is KEPT as its JSON text rather than dropped:
// a truncated branch an analyst can still read beats a hole they cannot see.
func TestDeepNestingIsBoundedWithoutLosingTheBranch(t *testing.T) {
	deep := `"leaf"`
	for i := 0; i < jsonlog.MaxDepth+6; i++ {
		deep = fmt.Sprintf(`{"n":%s}`, deep)
	}
	rec, err := jsonlog.Parse(deep, ingestedAt)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(valuesOf(rec.Fields), " ")
	if !strings.Contains(joined, "leaf") {
		t.Fatalf("the branch below the depth bound was DROPPED — an analyst sees a hole they cannot "+
			"know about, rather than a truncation they can: %v", rec.Fields)
	}
}

// BAD LINES ARE RETURNED, not logged and forgotten. An estate sends malformed lines, and discarding them
// silently is how a SIEM comes to be trusted for completeness it does not have.
func TestBadLinesAreReturnedAlongsideTheGoodOnes(t *testing.T) {
	body := "{\"a\":\"1\"}\nnot json\n\n{\"b\":\"2\"}\n[1,2]\n"
	recs, bad := jsonlog.ParseLines(body, ingestedAt)
	if len(recs) != 2 {
		t.Fatalf("parsed %d records, want 2", len(recs))
	}
	if len(bad) != 2 {
		t.Fatalf("reported %d bad lines, want 2 — a line nobody could read must not be indistinguishable "+
			"from a line nobody sent", len(bad))
	}
}

func valuesOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
