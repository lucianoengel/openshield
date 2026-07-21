package controlplane

import (
	"errors"
	"testing"

	"github.com/nats-io/nats.go"
)

// SEC-4: the server's async NATS error handler MUST count the drop — an in-package test so
// the exact counting the ErrorHandler wires (DroppedMessages) is asserted, catching a
// "swallow the error handler" mutation.
func TestNATSErrorHandlerCountsDrops(t *testing.T) {
	s := &Server{}
	if s.DroppedMessages.Load() != 0 {
		t.Fatal("counter not zero at start")
	}
	s.natsErrorHandler(nil, nil, nats.ErrSlowConsumer)
	s.natsErrorHandler(nil, nil, errors.New("some other async error"))
	if got := s.DroppedMessages.Load(); got != 2 {
		t.Errorf("DroppedMessages = %d, want 2 — the async error handler must count every drop (SEC-4)", got)
	}
}
