//go:build !linux

package canary

// Attribute cannot answer without a /proc to read.
//
// It returns Supported=false rather than an empty result, so a caller CANNOT read "no suspects" off a
// platform where nobody was ever looked at. That distinction is the whole contract of this type: the
// reassuring answer must never be produced by an inability to look.
func Attribute(string, int) Attribution { return Attribution{} }

// StartTicksForTest mirrors the Linux helper so the shared test file COMPILES everywhere, which is the
// point: cross-platform vet is what catches a test that only builds on the developer's own OS, and a
// build-tagged test file would have hidden this instead of surfacing it.
func StartTicksForTest(string) uint64 { return 0 }
