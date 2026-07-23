package nips

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestFetchFeed covers the conditional GET (NIPS-2 remote source): a 200 parses the served feed, a 304
// reports "not changed", and a non-200 / unparseable body is an error.
//
// Mutation: if FetchFeed ignored a non-200 status and parsed anyway, the 500 case would not error →
// this FAILs.
func TestFetchFeed(t *testing.T) {
	var mode struct {
		sync.Mutex
		status int
		body   string
		etag   string
	}
	set := func(status int, body, etag string) { mode.Lock(); mode.status, mode.body, mode.etag = status, body, etag; mode.Unlock() }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode.Lock()
		st, body, etag := mode.status, mode.body, mode.etag
		mode.Unlock()
		// Honor a conditional request when the test wants a 304.
		if st == http.StatusNotModified && r.Header.Get("If-None-Match") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.WriteHeader(st)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	ctx := context.Background()

	// 200 with a valid feed → parsed, changed, ETag returned.
	set(http.StatusOK, "domain evil.com\nip 1.2.3.4\n", `"v1"`)
	feed, etag, changed, err := FetchFeed(ctx, srv.Client(), srv.URL, "")
	if err != nil || !changed || feed == nil || feed.Size() != 2 || etag != `"v1"` {
		t.Fatalf("200 fetch: feed=%v size=%v changed=%v etag=%q err=%v", feed != nil, feedSize(feed), changed, etag, err)
	}

	// 304 with our ETag → not changed, no feed.
	set(http.StatusNotModified, "", "")
	f2, e2, changed2, err2 := FetchFeed(ctx, srv.Client(), srv.URL, `"v1"`)
	if err2 != nil || changed2 || f2 != nil || e2 != `"v1"` {
		t.Fatalf("304 fetch should be unchanged: feed=%v changed=%v etag=%q err=%v", f2 != nil, changed2, e2, err2)
	}

	// 500 with a PARSEABLE body → still an error (the status is checked, not just the parse). A bare
	// parse failure would mask a missing status check, so the body here is a valid feed.
	set(http.StatusInternalServerError, "domain notreal.com\n", "")
	if _, _, _, err := FetchFeed(ctx, srv.Client(), srv.URL, ""); err == nil {
		t.Error("a 500 response with a parseable body was not an error — the status check is missing")
	}

	// 200 with an unparseable feed → error (serve-stale).
	set(http.StatusOK, "notakind whatever\n", "")
	if _, _, _, err := FetchFeed(ctx, srv.Client(), srv.URL, ""); err == nil {
		t.Error("an unparseable feed body was not an error")
	}
}

func feedSize(f *Feed) int {
	if f == nil {
		return -1
	}
	return f.Size()
}

// TestURLFeedWatcherReloadsAndServesStale (NIPS-2): the watcher applies a CHANGED served feed and, on a
// server error, serves-stale (no apply, current feed kept).
//
// Mutation: if Watch applied on an error, the error tick would hand a nil/garbage feed to apply → the
// serve-stale assertion (no apply during the outage) FAILs.
func TestURLFeedWatcherReloadsAndServesStale(t *testing.T) {
	var mu sync.Mutex
	status, body, etag := http.StatusOK, "domain evil.com\n", `"a"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		st, b, e := status, body, etag
		mu.Unlock()
		if st == http.StatusNotModified && r.Header.Get("If-None-Match") == e {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if e != "" {
			w.Header().Set("ETag", e)
		}
		w.WriteHeader(st)
		_, _ = w.Write([]byte(b))
	}))
	defer srv.Close()

	var applied []int // sizes of applied feeds
	var errs int
	var amu sync.Mutex
	apply := func(f *Feed) { amu.Lock(); applied = append(applied, f.Size()); amu.Unlock() }
	onErr := func(error) { amu.Lock(); errs++; amu.Unlock() }
	lastApplied := func() int {
		amu.Lock()
		defer amu.Unlock()
		if len(applied) == 0 {
			return -1
		}
		return applied[len(applied)-1]
	}
	errCount := func() int { amu.Lock(); defer amu.Unlock(); return errs }

	// Seed the ETag from an initial fetch (as the gateway does), so an unchanged feed is a 304 no-op.
	_, initEtag, _, err := FetchFeed(context.Background(), srv.Client(), srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	w := NewURLFeedWatcher(srv.URL, srv.Client(), initEtag)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Watch(ctx, 15*time.Millisecond, apply, onErr)

	// Change the served feed (new indicator + new ETag) → the watcher applies it.
	mu.Lock()
	body, etag = "domain evil.com\ndomain worse.example\n", `"b"`
	status = http.StatusOK
	mu.Unlock()
	waitCond(t, func() bool { return lastApplied() == 2 })

	// Now make the server error → serve-stale: no NEW apply, errors counted.
	appliedBefore := lastApplied()
	mu.Lock()
	status = http.StatusInternalServerError
	mu.Unlock()
	waitCond(t, func() bool { return errCount() >= 1 })
	if lastApplied() != appliedBefore {
		t.Fatal("the watcher applied a feed during a server outage — serve-stale violated")
	}
}

func waitCond(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
