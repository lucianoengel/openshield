// Package attack maps OpenShield's detection signals to MITRE ATT&CK technique ids
// (SIEM-7). Every SOC speaks in techniques (T1567 exfiltration, T1552 credentials,
// T1218 system-binary-proxy); tagging detections with them makes alerts legible and
// gives the XDR correlation lane its sequence vocabulary. The mapping is a curated
// STARTER set over the signals OpenShield actually produces — not the full matrix —
// centralized in one place so a technique is only ever emitted because a real signal
// evidenced it.
package attack

import (
	"sort"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// Technique is a MITRE ATT&CK technique: a stable id and its name. Content-free.
type Technique struct {
	ID   string
	Name string
}

// Signals are the detection signals OpenShield computes, from which techniques are
// derived. All are content-free (types, categories, flags — no matched content).
type Signals struct {
	DetectorTypes     []corev1.DetectorType
	ThreatCategories  []corev1.ThreatCategory
	ExfilChannel      string // "cloud_sync" | "removable" | "local" | ""
	LOLBin            bool
	EncodedCommand    bool
	SuspiciousLineage bool
}

// Named techniques (the starter set).
var (
	tUnsecuredCredentials = Technique{"T1552", "Unsecured Credentials"}
	tAppLayerC2           = Technique{"T1071", "Application Layer Protocol"}
	tExfilCloudStorage    = Technique{"T1567.002", "Exfiltration to Cloud Storage"}
	tExfilPhysicalMedium  = Technique{"T1052", "Exfiltration Over Physical Medium"}
	tSystemBinaryProxy    = Technique{"T1218", "System Binary Proxy Execution"}
	tObfuscated           = Technique{"T1027", "Obfuscated Files or Information"}
	tCommandInterpreter   = Technique{"T1059", "Command and Scripting Interpreter"}
)

// allTechniques is the CLOSED vocabulary: every technique this package can emit, and therefore the
// only ids a Decision may legitimately carry (XDR-4b). Known() and Name() are both derived from it,
// so the mapper and the contract validator cannot disagree about the vocabulary by construction.
//
// The failure mode this shape exists to prevent is silent and one-directional: if the validator's
// set were maintained separately and the mapper started emitting a technique missing from it, every
// decision carrying that technique would be REFUSED at projection and the alert would never reach
// the stream. A dropped alert is indistinguishable from a quiet network.
var allTechniques = []Technique{
	tUnsecuredCredentials,
	tAppLayerC2,
	tExfilCloudStorage,
	tExfilPhysicalMedium,
	tSystemBinaryProxy,
	tObfuscated,
	tCommandInterpreter,
}

var techniqueByID = func() map[string]Technique {
	m := make(map[string]Technique, len(allTechniques))
	for _, t := range allTechniques {
		m[t.ID] = t
	}
	return m
}()

// Known reports whether an id names a technique this build can actually derive. The Decision contract
// uses it to refuse ids from outside the vocabulary, for the same reason it refuses an out-of-range
// confidence: a producer that is enrolled is not thereby trusted to be correct, and unified_alerts is
// a widely-read derived table.
func Known(id string) bool { _, ok := techniqueByID[id]; return ok }

// Name returns the display name for a technique id, and whether it is known.
//
// Only the ID crosses the contract; the name is looked up here, at display time, from THIS build's
// table. MITRE renames techniques, and a name copied into a hash-chained ledger is frozen at the
// moment of writing and cannot be corrected without breaking the chain.
func Name(id string) (string, bool) {
	t, ok := techniqueByID[id]
	return t.Name, ok
}

// Vocabulary returns every technique this build can emit, sorted by id — for a test, and for an
// operator asking what a technique-sequence hunt may name.
func Vocabulary() []Technique {
	out := append([]Technique(nil), allTechniques...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// credentialDetectors are the detector types that evidence unsecured credentials.
var credentialDetectors = map[corev1.DetectorType]bool{
	corev1.DetectorType_DETECTOR_TYPE_PRIVATE_KEY:    true,
	corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY: true,
	corev1.DetectorType_DETECTOR_TYPE_JWT:            true,
	corev1.DetectorType_DETECTOR_TYPE_API_TOKEN:      true,
}

// Techniques maps a signal set to the ATT&CK techniques it evidences, deduplicated
// by id and sorted. A signal set with no mappable signal yields none.
func Techniques(s Signals) []Technique {
	set := map[string]Technique{}
	add := func(t Technique) { set[t.ID] = t }

	for _, dt := range s.DetectorTypes {
		if credentialDetectors[dt] {
			add(tUnsecuredCredentials)
		}
	}
	// A known-bad destination (any threat-intel category) evidences C2.
	if len(s.ThreatCategories) > 0 {
		add(tAppLayerC2)
	}
	switch s.ExfilChannel {
	case "cloud_sync":
		add(tExfilCloudStorage)
	case "removable":
		add(tExfilPhysicalMedium)
	}
	if s.LOLBin {
		add(tSystemBinaryProxy)
	}
	if s.EncodedCommand {
		add(tObfuscated)
	}
	if s.SuspiciousLineage {
		add(tCommandInterpreter)
	}

	out := make([]Technique, 0, len(set))
	for _, t := range set {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IDs returns just the technique ids of a signal set — the compact form for the
// policy input and correlation.
func IDs(s Signals) []string {
	techs := Techniques(s)
	ids := make([]string, len(techs))
	for i, t := range techs {
		ids[i] = t.ID
	}
	return ids
}
