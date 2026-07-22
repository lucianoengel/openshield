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
