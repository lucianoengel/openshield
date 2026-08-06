// Package buildinfo carries the release version stamped into every OpenShield binary.
//
// ONE VARIABLE, STAMPED ONCE, and that is the whole design. `scripts/release.sh` built every artifact
// with `-ldflags "-X main.version=$VERSION"` and NO cmd/*/main.go ever declared a package-level
// `version` — the Go linker silently ignores an -X target that does not exist, so the flag has been
// decorative since it was written and every shipped binary carries no version at all.
//
// The obvious fix is a `var version` per command. It is the wrong one: release.sh builds twelve
// binaries, so that is twelve places to forget, and forgetting is exactly how this shipped. A thirteenth
// command added next month would repeat it in silence, because a missing -X target is a no-op rather
// than an error. Here there is one target, and a guard test asserts the path in the script still names
// a variable that exists.
package buildinfo

// Version is the release this binary was built from, injected at link time:
//
//	-ldflags "-X github.com/lucianoengel/openshield/internal/buildinfo.Version=v1.2.3"
//
// It defaults to "dev" rather than "" on purpose. An unstamped local build must be IDENTIFIABLE as an
// unstamped local build; an empty string on a fleet roster reads as "we could not tell", which is a
// different fact and the one this package exists to stop reporting by accident.
var Version = "dev"
