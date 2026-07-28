package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

// maxSunPath is the shortest unix-address limit across supported platforms: 104 bytes on macOS, 108 on
// Linux. The kernel refuses an over-long address with EINVAL — "bind: invalid argument" — which names
// neither the length nor the cause.
const maxSunPath = 104

// socketPath returns a socket path short enough to bind everywhere, and fails loudly if it is not.
//
// `t.TempDir()` embeds the TEST NAME, and on macOS the temp prefix alone is ~48 bytes — leaving about 31
// for the name before the address overflows. So a descriptive test name breaks the test on a platform
// nobody here develops on. That is not hypothetical: it took the CI macOS job down for over a day while
// every Linux run stayed green. Asserting the length HERE moves the failure to the machine of whoever
// wrote the test.
func socketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "os")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, name)
	if len(p) > maxSunPath {
		t.Fatalf("socket path is %d bytes, over the %d-byte unix address limit: %s", len(p), maxSunPath, p)
	}
	return p
}
