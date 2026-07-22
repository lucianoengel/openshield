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
