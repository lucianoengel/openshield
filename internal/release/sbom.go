package release

import (
	"debug/buildinfo"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Software Bill of Materials (PLAT-6).
//
// An SBOM is procurement table stakes now, and an UNSIGNED one is worthless: anyone can hand you a clean
// document about someone else's binary. So this is written into the release directory BEFORE the manifest
// is built, which means it is digested and covered by the manifest signature like every other artifact —
// tampering with the SBOM fails verification, and that property is what makes it evidence rather than
// paperwork.
//
// It is generated from the BINARIES, not from the source tree: `debug/buildinfo` reads the module graph
// the linker actually recorded in each artifact. A go.mod-derived SBOM describes what was intended; this
// describes what shipped, and when those disagree the second one is the one that matters.

// Component is one module an artifact was built from.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Hash is the module's checksum as the toolchain recorded it, when there is one. The main module and
	// anything replaced locally have none, and that absence is reported rather than filled in.
	Hash string `json:"hash,omitempty"`
}

// ArtifactSBOM is the dependency set of one shipped binary.
type ArtifactSBOM struct {
	Artifact   string      `json:"artifact"`
	GoVersion  string      `json:"go_version"`
	Main       string      `json:"main_module"`
	Components []Component `json:"components"`
}

// SBOM is the release's bill of materials, per artifact.
//
// Per ARTIFACT rather than one merged list, deliberately: the question an operator or an auditor asks is
// "does the thing I am running contain X", and a merged list answers "does anything in this release", which
// is a different and weaker claim.
type SBOM struct {
	Format    string         `json:"format"`
	Version   string         `json:"release_version"`
	Artifacts []ArtifactSBOM `json:"artifacts"`
}

// SBOMName is the file it is written to — an ordinary artifact, so the manifest covers it.
const SBOMName = "sbom.json"

// BuildSBOM reads every binary in dir and records the modules it was actually built from.
//
// A file that is not a Go binary is SKIPPED rather than failing the release: a release directory may
// legitimately contain other artifacts, and refusing to produce an SBOM because of one of them would mean
// releases ship without one.
func BuildSBOM(dir, version string) (SBOM, error) {
	s := SBOM{Format: "openshield-sbom/v1", Version: version}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return s, err
	}
	for _, e := range entries {
		if e.IsDir() || isMeta(e.Name()) || e.Name() == SBOMName {
			continue
		}
		info, err := buildinfo.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue // not a Go binary
		}
		a := ArtifactSBOM{Artifact: e.Name(), GoVersion: info.GoVersion, Main: info.Main.Path}
		for _, d := range info.Deps {
			// A REPLACED module is reported as what actually shipped, not as what was asked for — a
			// replace directive is exactly the case where the intended and the built graph diverge.
			m := d
			if d.Replace != nil {
				m = d.Replace
			}
			a.Components = append(a.Components, Component{
				Name: m.Path, Version: m.Version, Hash: strings.TrimSpace(m.Sum),
			})
		}
		sort.Slice(a.Components, func(i, j int) bool { return a.Components[i].Name < a.Components[j].Name })
		s.Artifacts = append(s.Artifacts, a)
	}
	sort.Slice(s.Artifacts, func(i, j int) bool { return s.Artifacts[i].Artifact < s.Artifacts[j].Artifact })
	return s, nil
}

// WriteSBOM writes the bill of materials into the release directory. Call it BEFORE Build, so the
// manifest digests it and the signature covers it.
func WriteSBOM(dir string, s SBOM) error {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SBOMName), body, 0o644)
}
