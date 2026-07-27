package fitness_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// EVERY EVENT PRODUCER MUST SET ITS OWN PROVENANCE (D307).
//
// `core.ValidateEvent` requires an event id, an agent id and a connector id. The engine's `attribute()`
// supplies the AGENT, the SUBJECT, the TIMESTAMP and the PURPOSE — the things it knows. It cannot invent
// an event's IDENTITY or its SOURCE, so a producer that omits either builds an event the pipeline
// rejects, `Process` returns an error, and the detection never happens.
//
// THIS HAS NOW HAPPENED THREE TIMES, and the third time it was five producers at once:
//
//   - D296: the fanotify connector omitted the PURPOSE, so the whole observe path was dead in the
//     shipped binary while every package test passed.
//   - D301: the exec gate omitted the event id and connector id, so the engine-backed inline exec path
//     denied nothing, ever.
//   - D307: clipboard, memory-scan, canary, print and FIM producers ALL omitted the connector id —
//     five endpoint detectors that detected, built an event, and had it thrown away.
//
// Three occurrences is not a coincidence, it is a missing check. Package tests never catch it because a
// test constructs the event it wants to test with every field already set; the omission only exists in
// the production constructor.
//
// It is a STATIC check for the same reason the scope-wiring guard is: catching it at runtime needs one
// integration scenario per producer, and a new producer would always be able to outrun that.

var eventLiteral = regexp.MustCompile(`&corev1\.Event\{`)

// providedByAttribute are the fields the engine stamps, so a producer need not.
// EventId and ConnectorId are NOT among them, by design — see above.
var producerMustSet = []string{"EventId", "ConnectorId"}

func TestEveryEventProducerSetsItsProvenance(t *testing.T) {
	root := filepath.Join("..", "..")
	var offences []string
	checked := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "node_modules", "openspec", ".claude", "corev1", "test":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		src := stripGoComments(string(b))
		for _, m := range eventLiteral.FindAllStringIndex(src, -1) {
			body, ok := braceBody(src, m[1])
			if !ok {
				continue
			}
			checked++
			var missing []string
			for _, f := range producerMustSet {
				if !strings.Contains(body, f+":") {
					missing = append(missing, f)
				}
			}
			if len(missing) > 0 {
				line := strings.Count(src[:m[0]], "\n") + 1
				offences = append(offences,
					filepath.ToSlash(path)+":"+strconv.Itoa(line)+" omits "+strings.Join(missing, ", "))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if checked == 0 {
		t.Fatal("no event literals were found, so this guard would pass vacuously")
	}
	if len(offences) > 0 {
		t.Errorf("%d event producer(s) omit provenance the engine cannot supply:\n  %s\n"+
			"    core.ValidateEvent requires an event id and a connector id. attribute() stamps the agent, "+
			"the subject, the timestamp and the purpose — it cannot invent an event's IDENTITY or its "+
			"SOURCE. A producer that omits either builds an event the pipeline REJECTS: the detector runs, "+
			"logs, and its detection is thrown away.",
			len(offences), strings.Join(offences, "\n  "))
	}
}

// braceBody returns the text between the brace at start-1 and its match.
func braceBody(src string, start int) (string, bool) {
	depth := 1
	for i := start; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start:i], true
			}
		}
	}
	return "", false
}
