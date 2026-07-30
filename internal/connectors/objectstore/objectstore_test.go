package objectstore

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The SIGNATURE itself is validated against a REAL MinIO in the integration suite, not here. A unit test
// that recomputed the expected signature with the same code under test would agree with whatever this
// implementation believes, which is this project's signature failure. A wrong signature is a 403 from a real
// server, so the external anchor (D64) is the server.
//
// What IS unit-testable is everything deterministic around it: the encoding rules a signature depends on,
// the pagination walk, the bounds, and above all the honesty of the coverage report.

func TestUriEncodeFollowsRfc3986NotQueryEscaping(t *testing.T) {
	// net/url's QueryEscape encodes a space as "+" and leaves some characters alone that AWS expects
	// percent-encoded. Either produces a signature mismatch, which surfaces as "SignatureDoesNotMatch" and
	// reads as a credentials problem — hours spent on the wrong thing.
	cases := []struct{ in, want string }{
		{"simple", "simple"},
		{"with space", "with%20space"},
		{"plus+sign", "plus%2Bsign"},
		{"tilde~ok", "tilde~ok"},
		{"slash/kept-by-caller", "slash%2Fkept-by-caller"},
		{"unicode-é", "unicode-%C3%A9"},
	}
	for _, c := range cases {
		if got := uriEncode(c.in); got != c.want {
			t.Errorf("uriEncode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalQueryIsSorted(t *testing.T) {
	// Sorting is required by the signature, not cosmetic: two orderings of the same parameters produce two
	// different signatures, and only one of them is accepted.
	req, _ := http.NewRequest(http.MethodGet, "http://h/b?list-type=2&prefix=z&continuation-token=a", nil)
	got := canonicalQuery(req.URL)
	want := "continuation-token=a&list-type=2&prefix=z"
	if got != want {
		t.Fatalf("canonicalQuery = %q, want %q", got, want)
	}
}

func TestHostIsSignedEvenThoughGoKeepsItOffTheHeaderMap(t *testing.T) {
	// Go stores Host on the request, not in Header. A signer that only walked Header would omit it, and S3
	// rejects that — a failure that looks like bad credentials and is not.
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/bucket", nil)
	signV4(req, Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"}, "us-east-1", emptyPayloadSHA256, fixedTime())
	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=host;") {
		t.Fatalf("host is not in SignedHeaders: %q", auth)
	}
	if req.Header.Get("x-amz-content-sha256") == "" {
		t.Error("x-amz-content-sha256 is required on every signed S3 request and was not set")
	}
}

func TestRangeIsSignedBecauseItChangesWhatComesBack(t *testing.T) {
	// Range decides WHICH BYTES are returned. Leaving it unsigned would let anything in the path rewrite it
	// without invalidating the signature — so a sweep could be silently fed different bytes than it asked
	// for, which for a scanner is the difference between reading the sensitive part and missing it.
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/bucket/key", nil)
	req.Header.Set("Range", "bytes=0-1023")
	signV4(req, Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"}, "us-east-1", emptyPayloadSHA256, fixedTime())
	if !strings.Contains(req.Header.Get("Authorization"), "range") {
		t.Fatalf("Range is not signed: %q", req.Header.Get("Authorization"))
	}
}

// fakeStore serves ListObjectsV2 pages and object bodies without checking signatures — the signature is the
// integration suite's job.
type fakeStore struct {
	pages   [][]string // keys per page
	bodies  map[string]string
	listHit int
}

func (f *fakeStore) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("list-type") == "2" {
			idx := 0
			if tok := r.URL.Query().Get("continuation-token"); tok != "" {
				_, _ = fmt.Sscanf(tok, "page-%d", &idx)
			}
			f.listHit++
			var b strings.Builder
			b.WriteString(`<ListBucketResult>`)
			for _, k := range f.pages[idx] {
				fmt.Fprintf(&b, `<Contents><Key>%s</Key><Size>%d</Size></Contents>`, k, len(f.bodies[k]))
			}
			if idx+1 < len(f.pages) {
				fmt.Fprintf(&b, `<IsTruncated>true</IsTruncated><NextContinuationToken>page-%d</NextContinuationToken>`, idx+1)
			} else {
				b.WriteString(`<IsTruncated>false</IsTruncated>`)
			}
			b.WriteString(`</ListBucketResult>`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/bucket/")
		body, ok := f.bodies[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	})
}

func newTestClient(t *testing.T, f *fakeStore, tune func(*Config)) *Client {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	cfg := Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "bucket",
		Creds: Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"},
	}
	if tune != nil {
		tune(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestListFollowsPagination(t *testing.T) {
	f := &fakeStore{
		pages:  [][]string{{"a", "b"}, {"c", "d"}, {"e"}},
		bodies: map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
	}
	c := newTestClient(t, f, nil)
	objs, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 5 {
		t.Fatalf("got %d objects, want 5 across 3 pages — a connector that reads only the first page reports "+
			"a bucket as smaller than it is, which is a clean result that is not one", len(objs))
	}
	if f.listHit != 3 {
		t.Errorf("made %d list calls, want 3", f.listHit)
	}
}

// TestATruncatedSweepReportsWhatItDidNotExamine is the assertion this feature most needs.
//
// A discovery sweep's output is a REASSURING ABSENCE. "No sensitive data found" is the answer nobody
// re-checks, so a sweep that quietly stopped at its ceiling and reported nothing is the most expensive
// failure this connector has — it converts "we did not look" into "there is nothing there".
func TestATruncatedSweepReportsWhatItDidNotExamine(t *testing.T) {
	f := &fakeStore{
		pages:  [][]string{{"a", "b", "c", "d", "e"}},
		bodies: map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
	}
	c := newTestClient(t, f, func(cfg *Config) { cfg.MaxObjects = 2 })
	objs, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 2 {
		t.Fatalf("got %d objects, want the ceiling of 2", len(objs))
	}
	if c.Skipped() != 3 {
		t.Fatalf("Skipped() = %d, want 3. A bound that truncates a sweep without saying so turns a partial "+
			"scan into a clean bill of health", c.Skipped())
	}
	s := NewSweeper(c, nil)
	for {
		ev, err := s.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ev == nil {
			break
		}
	}
	if got := s.Report().String(); !strings.Contains(got, "PARTIAL") || !strings.Contains(got, "3 NOT EXAMINED") {
		t.Fatalf("report does not say the sweep was partial: %q", got)
	}
}

func TestAReadableObjectYieldsAContentFreeEvent(t *testing.T) {
	const secretish = "CPF 111.444.777-35"
	f := &fakeStore{pages: [][]string{{"docs/report.txt"}}, bodies: map[string]string{"docs/report.txt": secretish}}
	c := newTestClient(t, f, nil)

	var storedID string
	var storedBody []byte
	s := NewSweeper(c, func(id string, b []byte) { storedID, storedBody = id, b })

	ev, err := s.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil {
		t.Fatal("no event for a readable object")
	}
	obj := ev.GetObject()
	if obj == nil {
		t.Fatal("the event carries no ObjectSubject")
	}
	if obj.GetBucket() != "bucket" || obj.GetKey() != "docs/report.txt" {
		t.Errorf("subject = %s/%s, want bucket/docs/report.txt", obj.GetBucket(), obj.GetKey())
	}
	if obj.GetBytesExamined() != int64(len(secretish)) {
		t.Errorf("bytes_examined = %d, want %d — reporting the CEILING rather than what was read would let a "+
			"partial scan look complete", obj.GetBytesExamined(), len(secretish))
	}
	// THE CONTENT WENT OUT OF BAND, and the event must not be able to carry it.
	if storedID != ev.GetEventId() || string(storedBody) != secretish {
		t.Fatalf("content was not stored for the worker under this event id (%q vs %q)", storedID, ev.GetEventId())
	}
	if strings.Contains(ev.String(), "111.444.777-35") {
		t.Fatal("object content appears on the Event — content must reach the sandboxed worker and nowhere " +
			"else (D10/D29/D72)")
	}
}

// TestContentIsStoredBeforeTheEventIsReturned pins the ordering smtpsource.go documents.
//
// Storing after dispatch races a resolver lookup that returns nothing, and "no content" is
// indistinguishable from "clean content" downstream — a scan that silently did not happen. On a discovery
// producer that is worse than elsewhere, because the whole output is an assertion about what is not there.
func TestContentIsStoredBeforeTheEventIsReturned(t *testing.T) {
	f := &fakeStore{pages: [][]string{{"k"}}, bodies: map[string]string{"k": "body"}}
	c := newTestClient(t, f, nil)
	stored := false
	s := NewSweeper(c, func(string, []byte) { stored = true })
	ev, err := s.Next(context.Background())
	if err != nil || ev == nil {
		t.Fatalf("no event: %v", err)
	}
	if !stored {
		t.Fatal("the event was returned before its content was stored — the pipeline can begin classifying " +
			"immediately, so the resolver would find nothing and the object would read as clean")
	}
}

func TestAnUnreadableObjectIsSkippedNotFatal(t *testing.T) {
	// One object we cannot read (a permission, an encryption key we do not hold) must not end a sweep over
	// everything else — but it must be COUNTED, or the sweep silently covers less than it claims.
	f := &fakeStore{
		pages:  [][]string{{"good", "missing", "also-good"}},
		bodies: map[string]string{"good": "a", "also-good": "b"},
	}
	c := newTestClient(t, f, nil)
	s := NewSweeper(c, nil)
	n := 0
	for {
		ev, err := s.Next(context.Background())
		if err != nil {
			t.Fatalf("one unreadable object ended the sweep: %v", err)
		}
		if ev == nil {
			break
		}
		n++
	}
	if n != 2 {
		t.Errorf("examined %d objects, want 2 readable ones", n)
	}
	if c.Skipped() != 1 {
		t.Errorf("Skipped() = %d, want 1 for the unreadable object", c.Skipped())
	}
}

func TestAConfigThatCouldOnlyReportACleanBucketIsRefused(t *testing.T) {
	// A sweep that cannot work must refuse to start rather than run and find nothing. "No sensitive data
	// found" produced by a misconfiguration is the worst output this feature can have.
	for _, c := range []struct {
		name string
		cfg  Config
	}{
		{"no endpoint", Config{Bucket: "b", Creds: Credentials{"AK", "SK"}}},
		{"no bucket", Config{Endpoint: "http://h", Creds: Credentials{"AK", "SK"}}},
		{"no credentials", Config{Endpoint: "http://h", Bucket: "b"}},
	} {
		if _, err := New(c.cfg); err == nil {
			t.Errorf("%s: accepted a configuration that cannot produce a meaningful sweep", c.name)
		}
	}
}

func TestTheStoreOnTheEventIsAHostNotACredentialBearingURL(t *testing.T) {
	// An Event is durable evidence read by people who should not be handed a secret, and an endpoint URL can
	// carry one.
	c, err := New(Config{
		Endpoint: "https://user:hunter2@minio.internal:9000",
		Bucket:   "b", Region: "r", Creds: Credentials{"AK", "SK"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.storeHost(); strings.Contains(got, "hunter2") || got != "minio.internal:9000" {
		t.Fatalf("storeHost() = %q, want the bare host", got)
	}
}

// fixedTime is a stable clock so signing tests are deterministic.
func fixedTime() time.Time { return time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC) }
