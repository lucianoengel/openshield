package casb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustCatalog(t *testing.T, text string) *Catalog {
	t.Helper()
	c, err := ParseCatalog(strings.NewReader(text))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

const sampleCatalog = `# operator cloud-service catalog
service dropbox category storage sanctioned
  host dropbox.com
  host dropboxusercontent.com
service pastebin category paste
  host pastebin.com
`

func TestClassifyMatchesServiceBySuffix(t *testing.T) {
	c := mustCatalog(t, sampleCatalog)
	// Exact and subdomain both match.
	for _, host := range []string{"dropbox.com", "api.dropbox.com", "dl.dropboxusercontent.com"} {
		m := c.Classify(host, "/", "POST")
		if m == nil || m.Service != "dropbox" {
			t.Fatalf("host %q → %v, want service dropbox", host, m)
		}
		if !m.Sanctioned {
			t.Errorf("dropbox should be sanctioned")
		}
	}
	// A look-alike suffix does NOT match (component-aware, not substring).
	if m := c.Classify("notdropbox.com", "/", "POST"); m != nil {
		t.Fatalf("notdropbox.com matched %v, want no match", m)
	}
	// A host in no service → nil.
	if m := c.Classify("example.com", "/", "POST"); m != nil {
		t.Fatalf("non-cloud host matched %v, want nil", m)
	}
}

func TestUploadIsMutatingMethod(t *testing.T) {
	c := mustCatalog(t, sampleCatalog)
	for _, method := range []string{"POST", "PUT", "PATCH", "post"} {
		if m := c.Classify("pastebin.com", "/", method); m == nil || !m.Upload {
			t.Errorf("%s should be an upload, got %v", method, m)
		}
	}
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		if m := c.Classify("pastebin.com", "/", method); m == nil || m.Upload {
			t.Errorf("%s should NOT be an upload, got %v", method, m)
		}
	}
}

func TestSanctionedFlag(t *testing.T) {
	c := mustCatalog(t, sampleCatalog)
	if m := c.Classify("pastebin.com", "/", "POST"); m == nil || m.Sanctioned {
		t.Errorf("pastebin should be UNsanctioned, got %v", m)
	}
	if m := c.Classify("dropbox.com", "/", "POST"); m == nil || !m.Sanctioned {
		t.Errorf("dropbox should be sanctioned, got %v", m)
	}
}

func TestEmptyCatalogIsInert(t *testing.T) {
	c := mustCatalog(t, "# just a comment\n")
	if !c.Empty() || c.Classify("dropbox.com", "/", "POST") != nil {
		t.Fatal("an empty catalog must match nothing")
	}
	var nilCat *Catalog
	if !nilCat.Empty() || nilCat.Classify("x", "/", "POST") != nil {
		t.Fatal("a nil catalog must be inert")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"host outside service": "host dropbox.com\n",
		"service no host":      "service a category storage\nservice b category paste\nhost b.com\n",
		"trailing no host":     "service a category storage\n",
		"missing category kw":  "service a storage\nhost a.com\n",
		"too few fields":       "service a\nhost a.com\n",
		"short host suffix":    "service a category storage\nhost co\n",
		"unknown directive":    "service a category storage\nfoo bar\n",
		"unknown flag":         "service a category storage extra\nhost a.com\n",
	}
	for name, text := range cases {
		if _, err := ParseCatalog(strings.NewReader(text)); err == nil {
			t.Errorf("%s: expected a parse error, got nil", name)
		}
	}
}

// SetCatalog / package Classify: the active catalog is nil-safe and swappable.
func TestActiveCatalogSwap(t *testing.T) {
	t.Cleanup(func() { SetCatalog(nil) })
	SetCatalog(nil)
	if Classify("dropbox.com", "/", "POST") != nil {
		t.Fatal("no active catalog → nil")
	}
	SetCatalog(mustCatalog(t, sampleCatalog))
	if m := Classify("dropbox.com", "/", "POST"); m == nil || m.Service != "dropbox" {
		t.Fatalf("active catalog classify = %v", m)
	}
}

func TestCatalogWatcherReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cat.txt")
	if err := os.WriteFile(path, []byte("service a category storage\nhost a-corp.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := NewCatalogWatcher(path) // synchronous baseline

	loaded := make(chan *Catalog, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Watch(ctx, 20*time.Millisecond, func(c *Catalog) { loaded <- c }, func(err error) { t.Error(err) })

	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(path, []byte("service a category storage sanctioned\nhost a-corp.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	touchFuture(t, path)

	select {
	case c := <-loaded:
		if m := c.Classify("a-corp.com", "/", "POST"); m == nil || !m.Sanctioned {
			t.Fatalf("reloaded catalog did not mark the service sanctioned: %v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher never reloaded the changed catalog")
	}
}

func touchFuture(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}
