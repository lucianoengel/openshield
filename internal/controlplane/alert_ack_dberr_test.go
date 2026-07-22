package controlplane_test

import (
	"context"
	"errors"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// R31 fold-in (SEC-11 family): a DB failure during the ack existence-probe must NOT masquerade as
// "alert not found". A closed pool yields a real error, distinct from ErrAlertNotFound.
func TestAcknowledgeAlertDBErrorIsNotNotFound(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	pool.Close() // simulate infrastructure failure

	_, err := srv.AcknowledgeAlert(context.Background(), 123, "operator:alice")
	if err == nil {
		t.Fatal("ack against a closed pool returned nil")
	}
	if errors.Is(err, controlplane.ErrAlertNotFound) {
		t.Error("a DB failure was reported as ErrAlertNotFound — error-vs-absence honesty violated")
	}
}
