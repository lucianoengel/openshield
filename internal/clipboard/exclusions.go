package clipboard

import (
	"path/filepath"
	"strings"
)

// Exclusions decides whether a copy from a given SOURCE application must never be read.
//
// This is a privacy control, and the ordering is the whole point: the check runs BEFORE the clipboard is
// read, not as a filter on the classification afterwards. A monitor that reads a password out of a vault
// and then discards the result has still read the password into its address space, put it in a buffer it
// may later log, and handed it to a classifier. "Discarded afterwards" is not the same as "never read".
//
// It exists because the honest description of a clipboard monitor is "it sees everything you copy" — which
// includes every credential copied out of a password manager. The platform already treats exclusion lists
// as a first-class policy primitive (D20/L1); this applies that primitive at the only point where it
// actually protects anything.
type Exclusions struct {
	// basenames are matched against the source executable's base name, lowercased.
	basenames map[string]bool
	// substrings catch wrappers and flatpak/snap paths where the basename is generic (e.g. an
	// AppImage or a `.../keepassxc/...` launcher shim).
	substrings []string
}

// DefaultExcludedSources are excluded unless an operator says otherwise.
//
// Password managers are the clear case: their entire purpose is to put a secret on the clipboard, and
// classifying those secrets is both useless (we know it is sensitive) and harmful (it is the one thing that
// must not be copied into a monitoring process). Defaulting to "read everything" for a component that sees
// every copy is not a defensible starting point.
var DefaultExcludedSources = []string{
	"keepassxc", "keepassx", "keepass",
	"bitwarden", "bitwarden-desktop",
	"1password", "1password-cli", "op",
	"gnome-keyring-daemon", "seahorse",
	"pass", "gopass",
	"enpass", "dashlane", "lastpass", "nordpass", "proton-pass",
	"secret-tool",
}

// NewExclusions builds the set from the defaults plus an operator's additions. An entry containing a path
// separator or a wildcard-ish fragment is treated as a substring match; anything else matches the
// executable's base name.
func NewExclusions(extra ...string) *Exclusions {
	e := &Exclusions{basenames: map[string]bool{}}
	for _, s := range append(append([]string{}, DefaultExcludedSources...), extra...) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if strings.ContainsAny(s, "/*") {
			e.substrings = append(e.substrings, strings.Trim(s, "*"))
			continue
		}
		e.basenames[s] = true
	}
	return e
}

// Excluded reports whether a copy from this source executable must not be read.
//
// An UNKNOWN source (empty path — the display server did not expose the owner, which is the normal case on
// Wayland) is NOT excluded. That is a deliberate and uncomfortable choice: it means Wayland cannot honor
// source exclusions, so a password-manager copy there IS read. Failing closed instead — excluding every
// unattributable copy — would silently disable clipboard monitoring entirely on Wayland while appearing to
// work, which is the worse failure. The capability report states which mode is in effect so an operator can
// decide with the facts.
func (e *Exclusions) Excluded(sourceExe string) bool {
	if e == nil || sourceExe == "" {
		return false
	}
	lower := strings.ToLower(sourceExe)
	if e.basenames[strings.ToLower(filepath.Base(sourceExe))] {
		return true
	}
	for _, sub := range e.substrings {
		if sub != "" && strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}
