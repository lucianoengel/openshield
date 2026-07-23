package worker_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lucianoengel/openshield/internal/agent/worker"
	"github.com/lucianoengel/openshield/internal/classify"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// The worker classifies inline content — the bytes a network-capable caller (the
// gateway) already holds — through the same detectors and the same bounded reader
// as a file, keeping the parser in the sandbox (D72).
func TestHandleClassifiesInlineContent(t *testing.T) {
	c := worker.Classifier(classify.New())
	resp := worker.Handle(context.Background(), c, nil, &corev1.ClassifyRequest{
		RequestId: "r1", EventId: "e1",
		Subject: &corev1.ClassifyRequest_Content{Content: []byte("cpf 111.444.777-35\n")},
	})
	if resp.GetError() != "" {
		t.Fatalf("unexpected error: %s", resp.GetError())
	}
	var cpf *corev1.DetectorHit
	for _, h := range resp.GetHits() {
		if h.GetDetectorType() == corev1.DetectorType_DETECTOR_TYPE_CPF {
			cpf = h
		}
	}
	if cpf == nil || cpf.GetCount() != 1 {
		t.Fatalf("expected 1 CPF hit from inline content, got %v", resp.GetHits())
	}
}

// Empty inline content is a clean no-hit result, not an error — distinguished from
// "no subject" (which IS an error) by the oneof type.
func TestHandleEmptyContentIsCleanNotError(t *testing.T) {
	c := worker.Classifier(classify.New())
	resp := worker.Handle(context.Background(), c, nil, &corev1.ClassifyRequest{
		RequestId: "r1", Subject: &corev1.ClassifyRequest_Content{Content: []byte{}},
	})
	if resp.GetError() != "" {
		t.Errorf("empty content reported an error: %s — empty is a clean result", resp.GetError())
	}
	if len(resp.GetHits()) != 0 {
		t.Errorf("empty content produced hits: %v", resp.GetHits())
	}
}

// Inline content over the ceiling is truncated, not read whole — the same bound as
// a file (a decompression/oversize body must hit a limit, D13).
func TestHandleContentHitsMaxBytes(t *testing.T) {
	c := worker.Classifier(classify.New())
	big := strings.Repeat("A", 1024)
	resp := worker.Handle(context.Background(), c, nil, &corev1.ClassifyRequest{
		RequestId: "r1", MaxBytes: 16,
		Subject: &corev1.ClassifyRequest_Content{Content: []byte(big)},
	})
	if resp.GetError() != "" {
		t.Fatalf("unexpected error: %s", resp.GetError())
	}
	if !resp.GetTruncated() {
		t.Errorf("content of %d bytes with max_bytes=16 was not reported truncated", len(big))
	}
}

// No subject is an error, never a clean empty result.
func TestHandleNoSubjectIsError(t *testing.T) {
	c := worker.Classifier(classify.New())
	resp := worker.Handle(context.Background(), c, nil, &corev1.ClassifyRequest{RequestId: "r1"})
	if resp.GetError() == "" {
		t.Error("a request with no subject produced no error")
	}
}
