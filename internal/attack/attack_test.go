package attack

import (
	"reflect"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

func TestTechniqueMapping(t *testing.T) {
	cases := []struct {
		name string
		sig  Signals
		want []string
	}{
		{"credential", Signals{DetectorTypes: []corev1.DetectorType{corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY}}, []string{"T1552"}},
		{"ioc domain", Signals{ThreatCategories: []corev1.ThreatCategory{corev1.ThreatCategory_THREAT_CATEGORY_IOC_DOMAIN}}, []string{"T1071"}},
		{"cloud + lolbin", Signals{ExfilChannel: "cloud_sync", LOLBin: true}, []string{"T1218", "T1567.002"}},
		{"removable", Signals{ExfilChannel: "removable"}, []string{"T1052"}},
		{"encoded command", Signals{EncodedCommand: true}, []string{"T1027"}},
		{"suspicious lineage", Signals{SuspiciousLineage: true}, []string{"T1059"}},
		{"none", Signals{ExfilChannel: "local"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IDs(c.sig)
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("IDs = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTechniquesDeduplicateAndSort(t *testing.T) {
	// Two credential detector types both evidence T1552 — each triggers an add, so
	// this exercises the de-dup (unlike a single-add signal).
	sig := Signals{DetectorTypes: []corev1.DetectorType{
		corev1.DetectorType_DETECTOR_TYPE_PRIVATE_KEY,
		corev1.DetectorType_DETECTOR_TYPE_AWS_ACCESS_KEY,
	}}
	got := IDs(sig)
	if len(got) != 1 || got[0] != "T1552" {
		t.Fatalf("dedup = %v, want exactly [T1552]", got)
	}

	// Multiple techniques come out sorted by id.
	multi := Signals{
		DetectorTypes:    []corev1.DetectorType{corev1.DetectorType_DETECTOR_TYPE_PRIVATE_KEY},
		ThreatCategories: []corev1.ThreatCategory{corev1.ThreatCategory_THREAT_CATEGORY_IOC_IP},
		ExfilChannel:     "removable",
	}
	ids := IDs(multi)
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Fatalf("techniques not sorted: %v", ids)
		}
	}
}

func TestTechniquesCarryNames(t *testing.T) {
	got := Techniques(Signals{ExfilChannel: "cloud_sync"})
	if len(got) != 1 || got[0].ID != "T1567.002" || got[0].Name == "" {
		t.Fatalf("Techniques = %v, want one named T1567.002", got)
	}
}

// TestEveryTechniqueTheMapperEmitsIsInTheVocabulary drives every signal the mapper can see
// through Techniques() and asserts each result is Known().
//
// This is the guard on a silent, one-directional failure. The Decision contract refuses a
// technique id outside the vocabulary (core.ValidateDecision), so a technique the mapper emits
// but Known() does not recognize would cause every decision carrying it to be REFUSED at
// projection — the alert would never reach unified_alerts at all. A dropped alert is
// indistinguishable from a quiet network, so nobody would find out.
func TestEveryTechniqueTheMapperEmitsIsInTheVocabulary(t *testing.T) {
	// Every signal field, at every value the mapper branches on.
	var sigs []Signals
	for dt := range credentialDetectors {
		sigs = append(sigs, Signals{DetectorTypes: []corev1.DetectorType{dt}})
	}
	sigs = append(sigs,
		Signals{ThreatCategories: []corev1.ThreatCategory{corev1.ThreatCategory_THREAT_CATEGORY_IOC_DOMAIN}},
		Signals{ExfilChannel: "cloud_sync"},
		Signals{ExfilChannel: "removable"},
		Signals{LOLBin: true},
		Signals{EncodedCommand: true},
		Signals{SuspiciousLineage: true},
	)
	emitted := map[string]bool{}
	for _, s := range sigs {
		for _, id := range IDs(s) {
			emitted[id] = true
			if !Known(id) {
				t.Fatalf("mapper emits %q but Known() refuses it — every decision carrying this "+
					"technique would be refused at projection and the alert silently dropped", id)
			}
			if name, ok := Name(id); !ok || name == "" {
				t.Fatalf("Name(%q) = %q, %v; want a display name", id, name, ok)
			}
		}
	}
	// The converse: a vocabulary entry no signal can reach is dead weight an operator could name
	// in a technique-sequence hunt that could never match.
	for _, tech := range Vocabulary() {
		if !emitted[tech.ID] {
			t.Errorf("%s (%s) is in the vocabulary but no signal shape emits it — a hunt naming "+
				"it would be accepted and could never match", tech.ID, tech.Name)
		}
	}
}

func TestUnknownTechniqueIdIsRefused(t *testing.T) {
	for _, id := range []string{"", "T9999", "t1552", "T1552 ", "T1567", "'; DROP TABLE"} {
		if Known(id) {
			t.Errorf("Known(%q) = true; want false", id)
		}
	}
	// T1567 deserves a note: T1567.002 IS emitted, and the parent is NOT. Rolling a sub-technique
	// up to its parent would be a claim the evidence does not make — the mapper derived
	// exfiltration to CLOUD STORAGE, not exfiltration over a web service generally.
	if !Known("T1567.002") {
		t.Fatal("T1567.002 should be known")
	}
}
