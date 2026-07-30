//go:build !unix

package quarantine_test

import "testing"

// Windows has no FIFO; the directory, missing-file and empty-target cases still cover the refusal.
func mkfifoTarget(*testing.T, string) string { return "" }
