// Package debpkg builds a Debian package from a VERIFIED release directory (PLAT-6 increment 2).
//
// WHY THIS EXISTS, AND IT IS NOT CONVENIENCE. The release pipeline produces reproducible binaries and a
// signed manifest over the SET (internal/release), and then deploy/install.sh ignores all of it and runs
// `go build` on the target host. An operator who follows the documented install path therefore ends up
// running binaries that were never signed, never verified, and not the ones anybody attested to — while
// the project's own README argues that this is precisely the posture to refuse. It also means every
// endpoint needs a Go toolchain, which no fleet wants.
//
// So the package is built FROM the signed artifact set, and Build REFUSES a directory that does not
// verify. That is the whole point of the type: the package inherits the release's integrity instead of
// being a second, unattested path to the same machine. A .deb that could be built from any pile of files
// would just be install.sh with a nicer name.
//
// NO NEW DEPENDENCY. A Debian binary package is an `ar` archive of three members in a fixed order, and ar
// plus tar plus gzip are all in the standard library. Shelling out to dpkg-deb would mean the release
// could only be built on a Debian host, which is the reproducibility property giving itself away.
//
// RPM IS NOT HERE, and is not stubbed. Its header is a binary format with its own index and type encoding
// — a real implementation, not a variation on this one. Claiming both and shipping one badly is worse
// than shipping one and saying so.
package debpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lucianoengel/openshield/internal/release"
)

// Spec describes the package to build.
type Spec struct {
	Name        string
	Version     string // upstream version, without a Debian revision
	Arch        string // Debian architecture name: amd64, arm64
	Maintainer  string
	Description string

	// Dir is the release directory: artifacts, SHA256SUMS.json and its signature.
	Dir string

	// PublicKey verifies the manifest. REQUIRED — see Build.
	PublicKey ed25519.PublicKey

	// UnitDir holds the systemd units to ship. Empty means none.
	UnitDir string
}

// Package is the built artifact, in memory. Callers write it where they like; keeping it out of the
// filesystem means the builder has nothing to clean up when a later step fails.
type Package struct {
	Filename string
	Bytes    []byte
	Files    []string // installed paths, in package order — what an operator gets
}

// binPrefix and unitPrefix are where the package installs.
//
// /usr/bin rather than /usr/local/bin: /usr/local is reserved for the local administrator and a package
// manager must not write there. install.sh's use of it is correct for a manual install and wrong for a
// package, which is the kind of difference that only shows up when both exist.
const (
	binPrefix  = "usr/bin"
	unitPrefix = "lib/systemd/system"
)

// Build produces the package.
//
// IT VERIFIES FIRST, AND A MISSING KEY IS AN ERROR RATHER THAN A SKIPPED CHECK. An unverifiable release
// directory is exactly the input this exists to refuse: packaging it would launder unattested binaries
// into a format an operator's tooling trusts by default, and `dpkg -i` asks no questions. Fail-closed
// here is not in tension with the fail-open enforcement contract — that governs traffic on a live host,
// while this decides what gets installed on one.
func Build(spec Spec) (*Package, error) {
	if len(spec.PublicKey) == 0 {
		return nil, fmt.Errorf("debpkg: no public key: a package must be built from a VERIFIED release, " +
			"and skipping the check would launder unattested binaries into a format dpkg installs " +
			"without asking")
	}
	if spec.Name == "" || spec.Version == "" || spec.Arch == "" {
		return nil, fmt.Errorf("debpkg: name, version and arch are all required")
	}
	if _, err := release.LoadAndVerifyWithKey(spec.Dir, spec.PublicKey); err != nil {
		return nil, fmt.Errorf("debpkg: the release directory does not verify, so there is nothing "+
			"trustworthy to package: %w", err)
	}

	data, files, installed, err := dataArchive(spec)
	if err != nil {
		return nil, err
	}
	control, err := controlArchive(spec, installed)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	// ORDER IS PART OF THE FORMAT: debian-binary, then control, then data. dpkg reads them in sequence
	// and a reordered archive is not a package.
	for _, m := range []struct {
		name string
		body []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", control},
		{"data.tar.gz", data},
	} {
		writeArMember(&out, m.name, m.body)
	}
	_ = files
	return &Package{
		Filename: fmt.Sprintf("%s_%s_%s.deb", spec.Name, spec.Version, spec.Arch),
		Bytes:    out.Bytes(),
		Files:    installed,
	}, nil
}

// writeArMember appends one ar member. Members are padded to an even length; a missing pad byte shifts
// every following header by one and dpkg reports the archive as corrupt.
func writeArMember(w io.Writer, name string, body []byte) {
	fmt.Fprintf(w, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(body))
	w.Write(body)
	if len(body)%2 == 1 {
		w.Write([]byte{'\n'})
	}
}

// releaseBinaries returns the artifacts in the release directory that belong in a Linux package for this
// architecture, keyed by the name they install under.
//
// The manifest records each artifact's platform, so the SELECTION comes from the manifest rather than
// from a hardcoded list that would silently drift as commands are added or dropped.
func releaseBinaries(spec Spec) (map[string]string, error) {
	m, err := release.LoadAndVerifyWithKey(spec.Dir, spec.PublicKey)
	if err != nil {
		return nil, err
	}
	want := "linux/" + spec.Arch
	out := map[string]string{}
	for _, e := range m.Entries {
		if e.Platform != want {
			continue
		}
		// The installed name drops the platform suffix the release uses to keep artifacts distinct in
		// one directory: an operator runs `openshield-engine`, not `openshield-engine-linux-amd64`.
		out[installName(path.Base(e.Name), spec.Arch)] = filepath.Join(spec.Dir, e.Name)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("debpkg: the release has no linux/%s artifacts, so this package would "+
			"install nothing while looking like a successful build", spec.Arch)
	}
	return out, nil
}

// dataArchive builds the filesystem payload.
func dataArchive(spec Spec) (gz []byte, names []string, installed []string, err error) {
	bins, err := releaseBinaries(spec)
	if err != nil {
		return nil, nil, nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	addDir := func(p string) error {
		return tw.WriteHeader(&tar.Header{Name: "./" + p + "/", Typeflag: tar.TypeDir, Mode: 0o755})
	}
	for _, d := range []string{"usr", binPrefix, "lib", "lib/systemd", unitPrefix} {
		if err := addDir(d); err != nil {
			return nil, nil, nil, err
		}
	}

	add := func(dest string, mode int64, body []byte) error {
		if err := tw.WriteHeader(&tar.Header{
			Name: "./" + dest, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		_, err := tw.Write(body)
		installed = append(installed, "/"+dest)
		return err
	}

	for _, name := range sortedKeys(bins) {
		body, err := os.ReadFile(bins[name])
		if err != nil {
			return nil, nil, nil, err
		}
		if err := add(path.Join(binPrefix, name), 0o755, body); err != nil {
			return nil, nil, nil, err
		}
		names = append(names, name)
	}

	if spec.UnitDir != "" {
		entries, err := os.ReadDir(spec.UnitDir)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".service") || strings.HasSuffix(e.Name(), ".timer")) {
				continue
			}
			body, err := os.ReadFile(filepath.Join(spec.UnitDir, e.Name()))
			if err != nil {
				return nil, nil, nil, err
			}
			if err := add(path.Join(unitPrefix, e.Name()), 0o644, body); err != nil {
				return nil, nil, nil, err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, nil, nil, err
	}
	return buf.Bytes(), names, installed, nil
}

// serviceUsers are the unprivileged accounts the units run as.
//
// THE PACKAGE CREATES THEM AND NEVER REMOVES THEM. A purge that deleted the engine's user would orphan
// the ledger signer state it owns — files whose uid no longer resolves — and a reinstall would get a
// different uid and be unable to read its own forward-secure state. Leaving a system user behind is
// untidy; making a tamper-evident ledger unreadable is worse.
var serviceUsers = []string{"openshield-engine", "openshield-worker", "openshield-server"}

// postinst creates the service users and reloads systemd. It does NOT enable or start anything: fanotify
// on an unconfigured host is the operator's call, which is the same choice install.sh makes and for the
// same reason.
func postinst() string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -e\n")
	for _, u := range serviceUsers {
		fmt.Fprintf(&b, "if ! getent passwd %s >/dev/null; then\n", u)
		fmt.Fprintf(&b, "  adduser --system --group --no-create-home --home /nonexistent %s || true\n", u)
		b.WriteString("fi\n")
	}
	b.WriteString("if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi\n")
	// SAID OUT LOUD, because a security package that installs silently and does nothing is
	// indistinguishable from one that is working.
	b.WriteString("echo 'openshield: installed. NOTHING IS ENABLED YET — configure, then'\n")
	b.WriteString("echo '  systemctl enable --now openshield-engine.service'\n")
	b.WriteString("exit 0\n")
	return b.String()
}

// prerm stops units before the files go away, so systemd is not left supervising deleted binaries.
func prerm() string {
	return "#!/bin/sh\nset -e\n" +
		"if [ -d /run/systemd/system ]; then\n" +
		"  for u in openshield-engine openshield-gateway openshield-server openshield-agent; do\n" +
		"    systemctl stop $u.service 2>/dev/null || true\n" +
		"  done\n" +
		"fi\nexit 0\n"
}

// controlArchive builds the metadata member.
func controlArchive(spec Spec, installed []string) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)

	ctrl := fmt.Sprintf(`Package: %s
Version: %s
Section: admin
Priority: optional
Architecture: %s
Maintainer: %s
Description: %s
`, spec.Name, spec.Version, spec.Arch, spec.Maintainer, firstLine(spec.Description))

	for _, f := range []struct {
		name string
		mode int64
		body string
	}{
		{"control", 0o644, ctrl},
		{"postinst", 0o755, postinst()},
		{"prerm", 0o755, prerm()},
	} {
		if err := tw.WriteHeader(&tar.Header{
			Name: "./" + f.name, Mode: f.mode, Size: int64(len(f.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// firstLine keeps a Description to its synopsis line; a multi-line one needs continuation-space framing
// that a malformed value silently breaks.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "OpenShield data security platform"
	}
	return s
}

// installName strips a release artifact's platform suffix.
//
// The release names artifacts cmd_goos_goarch so one directory can hold every platform — the same
// convention the manifest's platformOf parses. Installing `openshield-engine_linux_amd64` into /usr/bin
// would leave every systemd unit, every document and every operator's muscle memory pointing at a binary
// that is not there.
func installName(artifact, arch string) string {
	return strings.TrimSuffix(artifact, "_linux_"+arch)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
