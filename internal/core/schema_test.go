package core_test

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// These tests assert the SHAPE of the contract, not behaviour. They exist
// because several project invariants are only real if violating them fails the
// build. A comment saying "do not add content fields here" is not an invariant.

func fieldNames(m protoreflect.MessageDescriptor) []string {
	var out []string
	for i := 0; i < m.Fields().Len(); i++ {
		out = append(out, string(m.Fields().Get(i).Name()))
	}
	sort.Strings(out)
	return out
}

// TestActionEnumIsClosed pins the action set.
//
// If this test fails because you added an action, that is the test working as
// designed. An open action surface would let a compromised control plane
// express "upload file to URL" (D14) — adding to the set should require a
// deliberate edit here, not just in the proto.
func TestActionEnumIsClosed(t *testing.T) {
	want := []string{
		"ACTION_UNSPECIFIED",
		"ACTION_ALLOW",
		"ACTION_ALERT",
		"ACTION_BLOCK",
		"ACTION_QUARANTINE_LOCAL",
		"ACTION_ENCRYPT_LOCAL",
		// Network verdict (N1/D69): coach/justify redirect. Block-vs-reset is an
		// enforcement mode, not a verdict, so it deliberately gets no action.
		"ACTION_REDIRECT",
	}
	vals := corev1.Action(0).Descriptor().Values()
	if vals.Len() != len(want) {
		t.Fatalf("Action enum has %d members, want %d — if you added an action, "+
			"update this test deliberately", vals.Len(), len(want))
	}
	got := map[string]bool{}
	for i := 0; i < vals.Len(); i++ {
		got[string(vals.Get(i).Name())] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("Action enum missing %s", w)
		}
	}
}

// TestDecisionCarriesNoParameters asserts there is no sibling field through
// which an action could be parameterised — no URL, host, path or command.
// A closed enum is worthless if a neighbouring string carries the destination.
func TestDecisionCarriesNoParameters(t *testing.T) {
	md := (&corev1.Decision{}).ProtoReflect().Descriptor()
	banned := []string{"url", "uri", "host", "path", "command", "cmd", "target",
		"destination", "endpoint", "address", "params", "args", "script"}
	for i := 0; i < md.Fields().Len(); i++ {
		name := strings.ToLower(string(md.Fields().Get(i).Name()))
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("Decision.%s looks like an action parameter (matched %q); "+
					"the action set must stay closed and unparameterised (D14)",
					md.Fields().Get(i).Name(), b)
			}
		}
		// A map field is the classic escape hatch — params map<string,string>.
		if md.Fields().Get(i).IsMap() {
			t.Errorf("Decision.%s is a map; that is an open parameter surface",
				md.Fields().Get(i).Name())
		}
	}
}

// TestDecisionHasNoDetectionInternals asserts a Decision is explainable to an
// investigator but opaque about detection. Enforcers see this message; they
// must not learn which classifier or pattern produced it.
func TestDecisionHasNoDetectionInternals(t *testing.T) {
	md := (&corev1.Decision{}).ProtoReflect().Descriptor()
	banned := []string{"classifier", "detector", "pattern", "regex", "model",
		"match", "excerpt", "content", "snippet", "sample"}
	for i := 0; i < md.Fields().Len(); i++ {
		name := strings.ToLower(string(md.Fields().Get(i).Name()))
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("Decision.%s exposes detection internals (matched %q); "+
					"enforcers receive only the Decision", md.Fields().Get(i).Name(), b)
			}
		}
	}
}

// TestClassificationSummaryFieldSetIsExact pins the wire form's fields.
//
// The summary is the only classification shape permitted off-host. Any added
// field is a potential channel for content, so adding one must fail CI and be
// justified rather than slipping through review (D10).
func TestClassificationSummaryFieldSetIsExact(t *testing.T) {
	got := fieldNames((&corev1.ClassificationSummary{}).ProtoReflect().Descriptor())
	want := []string{"confidence", "detector_type", "event_id", "match_count"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ClassificationSummary fields = %v, want exactly %v — "+
			"this is the only classification form allowed off-host", got, want)
	}
}

// TestClassificationSummaryCannotCarryContent asserts the wire form has no
// field capable of holding content, a hash, a fingerprint or an embedding.
//
// Embeddings are content: similarity-preserving hashes leak structure by
// construction, and dense embeddings are invertible (D11).
func TestClassificationSummaryCannotCarryContent(t *testing.T) {
	md := (&corev1.ClassificationSummary{}).ProtoReflect().Descriptor()
	for i := 0; i < md.Fields().Len(); i++ {
		f := md.Fields().Get(i)
		if f.Kind() == protoreflect.BytesKind {
			t.Errorf("ClassificationSummary.%s is bytes — could carry content or a digest", f.Name())
		}
		if f.IsList() && (f.Kind() == protoreflect.FloatKind || f.Kind() == protoreflect.DoubleKind) {
			t.Errorf("ClassificationSummary.%s is a float vector — embeddings are content (D11)", f.Name())
		}
		name := strings.ToLower(string(f.Name()))
		for _, b := range []string{"hash", "digest", "fingerprint", "embedding",
			"vector", "text", "content", "excerpt", "sample"} {
			if strings.Contains(name, b) {
				t.Errorf("ClassificationSummary.%s matched banned substring %q", f.Name(), b)
			}
		}
	}
}

// TestDetectorTypeIsEnum guards against a free-form detector name, which could
// itself leak what it detected — a detector named for a customer or a person.
func TestDetectorTypeIsEnum(t *testing.T) {
	md := (&corev1.ClassificationSummary{}).ProtoReflect().Descriptor()
	f := md.Fields().ByName("detector_type")
	if f == nil {
		t.Fatal("ClassificationSummary has no detector_type field")
	}
	if f.Kind() != protoreflect.EnumKind {
		t.Errorf("detector_type is %v, want enum — a free-form name can leak what it detected", f.Kind())
	}
}

// TestEventHasNoUnexpectedBytesFields allowlists the opaque identifiers that
// legitimately need bytes, so that adding any other bytes field fails CI.
//
// The allowlist is the point: kernel file handles are genuinely opaque binary,
// but "we needed bytes here" is exactly how content leaks in.
func TestEventHasNoUnexpectedBytesFields(t *testing.T) {
	allowed := map[string]string{
		"file_handle":   "opaque fanotify FID handle (T-005)",
		"parent_handle": "opaque fanotify DFID handle (T-005)",
	}
	var walk func(md protoreflect.MessageDescriptor, path string, seen map[string]bool)
	walk = func(md protoreflect.MessageDescriptor, path string, seen map[string]bool) {
		if seen[string(md.FullName())] {
			return
		}
		seen[string(md.FullName())] = true
		for i := 0; i < md.Fields().Len(); i++ {
			f := md.Fields().Get(i)
			if f.Kind() == protoreflect.BytesKind {
				if _, ok := allowed[string(f.Name())]; !ok {
					t.Errorf("%s.%s is an unallowlisted bytes field — Events carry "+
						"metadata and references, never content (D10)", path, f.Name())
				}
			}
			if f.Kind() == protoreflect.MessageKind {
				walk(f.Message(), path+"."+string(f.Name()), seen)
			}
		}
	}
	walk((&corev1.Event{}).ProtoReflect().Descriptor(), "Event", map[string]bool{})
}

// TestFilesystemSubjectHasThreeIdentityForms pins the arity that T-005
// measured. An earlier version of the schema had two; the spike showed three.
func TestFilesystemSubjectHasThreeIdentityForms(t *testing.T) {
	md := (&corev1.FilesystemSubject{}).ProtoReflect().Descriptor()
	oneofs := md.Oneofs()
	if oneofs.Len() != 1 {
		t.Fatalf("FilesystemSubject has %d oneofs, want 1", oneofs.Len())
	}
	got := oneofs.Get(0).Fields().Len()
	if got != 3 {
		t.Errorf("identity oneof has %d forms, want 3 (resolved_path, file_handle, "+
			"parent_and_name) — see docs/spike-t005-fanotify.md", got)
	}
}
