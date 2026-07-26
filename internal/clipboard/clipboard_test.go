package clipboard_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/clipboard"
)

// fakeReader is the OS seam, and the ONLY thing faked in this package's tests: everything above it — change
// detection, bounding, the producer, the pipeline — is the real code.
type fakeReader struct {
	contents []string // returned in order; the last one repeats once exhausted
	calls    int
	err      error
}

func (f *fakeReader) Read(context.Context) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	i := f.calls
	f.calls++
	if i >= len(f.contents) {
		i = len(f.contents) - 1
	}
	if i < 0 {
		return nil, nil
	}
	return []byte(f.contents[i]), nil
}

func (f *fakeReader) DisplayServer() string { return clipboard.DisplayX11 }

// TestDetectPrefersWaylandAndReportsNone: the no-display case is the one that matters — it is what tells the
// producer to disable itself loudly instead of polling forever with nothing to see.
func TestDetectPrefersWaylandAndReportsNone(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("DISPLAY", ":0")
	if got := clipboard.Detect(); got != clipboard.DisplayWayland {
		t.Errorf("with both set, Detect() = %q, want %q (the native path is the accurate one)",
			got, clipboard.DisplayWayland)
	}
	t.Setenv("WAYLAND_DISPLAY", "")
	if got := clipboard.Detect(); got != clipboard.DisplayX11 {
		t.Errorf("with only DISPLAY, Detect() = %q, want %q", got, clipboard.DisplayX11)
	}
	t.Setenv("DISPLAY", "")
	if got := clipboard.Detect(); got != clipboard.DisplayNone {
		t.Errorf("with no display, Detect() = %q, want none — the producer must disable itself", got)
	}
}

// TestWatcherReportsOnlyChanges: an unchanged clipboard must not become an exfiltration event every poll, or
// an idle desktop alerts once per interval forever.
//
// Mutation: ignore the digest (always report) → the repeat assertions FAIL.
func TestWatcherReportsOnlyChanges(t *testing.T) {
	r := &fakeReader{contents: []string{"secret one", "secret one", "secret one", "secret two", "secret one"}}
	w := &clipboard.Watcher{Reader: r}
	ctx := context.Background()

	var got []string
	for i := 0; i < 5; i++ {
		b, changed, err := w.Poll(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			got = append(got, string(b))
		}
	}
	// One event for the first content, one for the change, one for changing BACK — the watcher tracks the
	// LAST content, not a history, so re-copying an earlier item is a real new copy.
	want := "secret one|secret two|secret one"
	if strings.Join(got, "|") != want {
		t.Fatalf("changes = %v, want [%s]", got, want)
	}
}

// TestWatcherTreatsClearedClipboardAsChangeWithNoContent: clearing the clipboard is a change, but there is
// nothing to classify — reporting empty bytes as a copy would produce an alert about nothing.
func TestWatcherTreatsClearedClipboardAsChangeWithNoContent(t *testing.T) {
	r := &fakeReader{contents: []string{"something", ""}}
	w := &clipboard.Watcher{Reader: r}
	ctx := context.Background()

	if _, changed, _ := w.Poll(ctx); !changed {
		t.Fatal("first content was not reported as a change")
	}
	b, changed, err := w.Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed || len(b) != 0 {
		t.Fatalf("a cleared clipboard reported (changed=%v, %d bytes), want no reportable copy", changed, len(b))
	}
}

// TestWatcherPropagatesReaderErrors: a broken helper must surface, not look like an empty clipboard.
func TestWatcherPropagatesReaderErrors(t *testing.T) {
	sentinel := errors.New("helper exploded")
	w := &clipboard.Watcher{Reader: &fakeReader{err: sentinel}}
	if _, _, err := w.Poll(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the reader's error", err)
	}
}

// TestContentStoreResolvesOnceAndReleases: content must not be retained after classification, or a
// long-running engine grows with every copy the user makes.
func TestContentStoreResolvesOnceAndReleases(t *testing.T) {
	s := clipboard.NewContentStore(nil)
	s.Put("evt-1", []byte("payload"))
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
	if got := string(s.Resolve("evt-1")); got != "payload" {
		t.Fatalf("Resolve = %q, want payload", got)
	}
	if s.Len() != 0 {
		t.Errorf("content was retained after being resolved (Len = %d)", s.Len())
	}
	if got := s.Resolve("evt-1"); got != nil {
		t.Errorf("second Resolve returned %q, want nil — the entry must be released", got)
	}
}

// TestContentStoreChainsToAnExistingResolver is the regression guard for the seam: engine.SetContentResolver
// holds ONE function, so installing the clipboard store must not displace another producer's source.
//
// Mutation: overwrite instead of chaining → the SMTP-style event resolves to nothing → this FAILS.
func TestContentStoreChainsToAnExistingResolver(t *testing.T) {
	existing := func(eventID string) []byte {
		if eventID == "smtp-1" {
			return []byte("an email body")
		}
		return nil
	}
	s := clipboard.NewContentStore(existing)
	s.Put("clip-1", []byte("clipboard text"))

	if got := string(s.Resolve("clip-1")); got != "clipboard text" {
		t.Errorf("clipboard content = %q, want its own", got)
	}
	if got := string(s.Resolve("smtp-1")); got != "an email body" {
		t.Errorf("the pre-existing resolver returned %q — installing the clipboard store displaced it", got)
	}
	if got := s.Resolve("unknown"); got != nil {
		t.Errorf("unknown event resolved to %q, want nil", got)
	}
}

// TestContentStoreIsBounded: overflow drops the OLDEST unresolved entry, never the newest — the item just
// copied is the one about to be classified.
func TestContentStoreIsBounded(t *testing.T) {
	s := clipboard.NewContentStore(nil)
	s.Max = 3
	for _, id := range []string{"a", "b", "c", "d"} {
		s.Put(id, []byte(id+"-content"))
	}
	if s.Len() != 3 {
		t.Fatalf("Len = %d, want 3 (the bound must hold)", s.Len())
	}
	if got := s.Resolve("a"); got != nil {
		t.Error("the OLDEST entry survived the bound; it should have been dropped")
	}
	if got := string(s.Resolve("d")); got != "d-content" {
		t.Errorf("the NEWEST entry = %q, want it retained — it is the live detection", got)
	}
}

// countingReader records whether it was ever asked to read — the assertion that matters for exclusions.
type countingReader struct{ reads int }

func (c *countingReader) Read(context.Context) ([]byte, error) {
	c.reads++
	return []byte("the master password"), nil
}
func (c *countingReader) DisplayServer() string { return clipboard.DisplayX11 }

// TestExclusionsCoverPasswordManagersByDefault: the default list must protect the obvious case without an
// operator having to think of it.
func TestExclusionsCoverPasswordManagersByDefault(t *testing.T) {
	e := clipboard.NewExclusions()
	for _, exe := range []string{
		"/usr/bin/keepassxc", "/usr/bin/bitwarden", "/opt/1Password/1password",
		"/usr/bin/KeePassXC", "/usr/bin/gnome-keyring-daemon", "/usr/bin/pass",
	} {
		if !e.Excluded(exe) {
			t.Errorf("%s is not excluded by default — a monitor that reads every copy would read every "+
				"credential copied out of it", exe)
		}
	}
	for _, exe := range []string{"/usr/bin/libreoffice", "/usr/bin/firefox", "/usr/bin/code"} {
		if e.Excluded(exe) {
			t.Errorf("%s is excluded by default; only credential sources should be", exe)
		}
	}
}

// TestExclusionsAcceptOperatorEntries: basenames and path substrings (flatpak/snap/AppImage shims).
func TestExclusionsAcceptOperatorEntries(t *testing.T) {
	e := clipboard.NewExclusions("my-vault", "/opt/secrets/")
	if !e.Excluded("/usr/local/bin/my-vault") {
		t.Error("an operator-added basename was not excluded")
	}
	if !e.Excluded("/opt/secrets/launcher.sh") {
		t.Error("an operator-added path substring was not excluded")
	}
	if e.Excluded("/usr/bin/vim") {
		t.Error("an unrelated binary was excluded")
	}
}

// TestUnknownSourceIsNotExcluded pins the deliberate choice: an unattributable copy (the normal Wayland
// case) is NOT excluded, because failing closed would silently disable monitoring entirely while appearing
// to work. The capability report is what tells the operator which mode they are in.
func TestUnknownSourceIsNotExcluded(t *testing.T) {
	if clipboard.NewExclusions().Excluded("") {
		t.Error("an unknown source was excluded — that silently disables monitoring wherever attribution " +
			"is unavailable")
	}
}

// TestExcludedSourceIsNeverRead is the ordering assertion, and the reason this control exists: the content
// must never be READ, not merely discarded after reading.
//
// Mutation: read first and filter the result afterwards → reads > 0 → this FAILS.
func TestExcludedSourceIsNeverRead(t *testing.T) {
	r := &countingReader{}
	w := &clipboard.Watcher{Reader: r, Exclusions: clipboard.NewExclusions(), Source: func() string {
		return "/usr/bin/keepassxc"
	}}
	b, changed, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed || len(b) != 0 {
		t.Errorf("an excluded source produced content (changed=%v, %d bytes)", changed, len(b))
	}
	if r.reads != 0 {
		t.Fatalf("the clipboard was READ %d times for an excluded source — the secret entered the process; "+
			"exclusion must happen BEFORE the read, not as a filter after it", r.reads)
	}
}
