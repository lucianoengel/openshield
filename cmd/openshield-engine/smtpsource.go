package main

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/connectors/smtp"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// smtpListener binds the SMTP capture connector and returns a Listener whose sink feeds each parsed
// message — as an SMTP_MESSAGE Event — into the SAME event channel the file watchers and the DNS
// connector use, so an outbound email runs classify → policy → decide → audit exactly like a file write.
//
// THE CONNECTOR WAS COMPLETE AND STARTED BY NOTHING. Parser, capture listener with per-session ceilings,
// idle timeouts and a concurrency cap, event producer, full unit tests — and no binary imported the
// package, with no setting that could have turned it on. It could not run in any deployment however
// configured, while the README described the product as performing live SMTP inspection. This file is
// the missing wire, and it is deliberately the same shape as dnssource.go: two connectors that entered
// the pipeline differently would be two ways for a source to be wrong.
//
// THE BODY TRAVELS OUT OF BAND (ENG-1), not on the Event. `smtp.ToEvent` carries the envelope — the
// recipient domain as the flow's destination — and nothing else, because an Event carrying message text
// would put content into the audit path and into every consumer of the bus (D10/D29). The bytes go into
// a content store the engine's resolver consults, so they reach the SANDBOXED WORKER and nowhere else
// (D72): an email body is attacker-controlled input, and the process that parses it is the one that must
// hold neither the network nor the keys.
//
// The engine stays observe-only (D1); this is an additional SOURCE, not an enforcement path.
func smtpListener(ctx context.Context, addr string, store *clipboard.ContentStore,
	events chan<- *corev1.Event, log *slog.Logger) (*smtp.Listener, error) {
	var flowSeq atomic.Uint64
	return smtp.Listen(addr, func(m *smtp.Message) {
		flowID := strconv.FormatUint(flowSeq.Add(1), 10)
		ev := smtp.ToEvent(flowID, "", m)
		// STORED BEFORE THE SEND, not after. The pipeline can begin classifying the moment the event is
		// received, so a store that happened afterwards would race a resolver lookup that returns
		// nothing — and "no content" is indistinguishable from "clean content" downstream, which is a
		// scan that silently did not happen.
		store.Put(ev.GetEventId(), m.Body)
		select {
		case events <- ev:
		case <-ctx.Done():
			// Abandon the send rather than block the listener's accept loop on shutdown.
		}
	}, log)
}
