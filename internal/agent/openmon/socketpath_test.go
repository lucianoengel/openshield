package openmon_test

import (
	"os"
	"path/filepath"
	"testing"
)

// maxSunPath is the shortest limit any supported platform imposes on a unix socket address.
//
// `sockaddr_un.sun_path` is 108 bytes on Linux and 104 on macOS, and the kernel does not truncate — it
// refuses the bind with EINVAL, reported as "bind: invalid argument". Nothing in that message mentions
// length, so it reads as a broken socket rather than a long path.
const maxSunPath = 104

// socketPath returns a unix socket path short enough to bind on every supported platform, and FAILS
// LOUDLY if it is not.
//
// `t.TempDir()` cannot be used for a socket, and the reason is a trap worth naming: it embeds the TEST'S
// NAME in the directory. On macOS the temp prefix is already ~48 bytes
// (`/var/folders/8j/sfr9qqcj73j4p6nhwcfpr0th0000gn/T/`), which leaves about 31 bytes for the test name
// before the address overflows — so a DESCRIPTIVE test name breaks the test, and a short one hides the
// problem. That is exactly what happened: `TestMismatchedResponseIDIsRejected` (33 characters) failed on
// the macOS CI runner while every Linux run passed, for over a day.
//
// The length assertion is the point of this helper. Without it the constraint is only enforced by a
// platform none of us develops on, so it is discovered in CI, by someone who did not write the test.
func socketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "os")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, name)
	if len(p) > maxSunPath {
		t.Fatalf("socket path is %d bytes, over the %d-byte limit a unix address allows: %s\n"+
			"bind would fail with 'invalid argument', which names neither the length nor the cause",
			len(p), maxSunPath, p)
	}
	return p
}

// TestASocketPathFitsTheAddressLimit proves the helper's own guarantee, and would have caught the CI
// failure on a Linux workstation.
func TestASocketPathFitsTheAddressLimit(t *testing.T) {
	if p := socketPath(t, "e.sock"); len(p) > maxSunPath {
		t.Errorf("socketPath returned %d bytes: %s", len(p), p)
	}
}
