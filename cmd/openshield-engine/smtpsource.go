package main

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lucianoengel/openshield/internal/clipboard"
	"github.com/lucianoengel/openshield/internal/connectors/smtp"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/engine"
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
// The engine stays observe-only (D1) unless enforcement is switched on; see smtpFilter, which turns this
// same source into the mail path's enforcement point.
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

// smtpFilter is the DECIDE hook that turns the SMTP connector from a capture endpoint into a filtering
// one — the NIPS gap the README named: "SMTP is captured and inspected, not filtered — nothing is blocked
// on the mail path". Mail is the exfil channel a DLP product exists to cover, and inspection that cannot
// refuse is a report written after the data left.
//
// It runs the SAME pipeline the sink would have, synchronously, because the reply to the final "." of
// DATA is the only moment SMTP offers to refuse a message. Afterwards the client considers it accepted,
// so a verdict reached later can report but cannot prevent — the same reason the clipboard mediator
// decides at paste time and the print filter aborts inside the CUPS chain rather than after.
//
// FAIL-OPEN, DELIBERATELY AND IN BOTH DIRECTIONS (D17/D18):
//
//   - a pipeline ERROR accepts the message. Refusing mail because the classifier was unavailable is how a
//     DLP product takes out a mail server, and the failure is invisible to the sender either way.
//   - a pipeline TIMEOUT accepts it too, and the deadline exists so a stuck classification cannot hold an
//     SMTP session open indefinitely — a client blocked at "." is a message neither delivered nor refused.
//
// Both are logged, because an accept that happened because something broke must not look like an accept
// the policy chose (D31).
func smtpFilter(ctx context.Context, eng *engine.Engine, store *clipboard.ContentStore,
	timeout time.Duration, log *slog.Logger) func(*smtp.Message) bool {
	var flowSeq atomic.Uint64
	return func(m *smtp.Message) bool {
		flowID := strconv.FormatUint(flowSeq.Add(1), 10)
		ev := smtp.ToEvent(flowID, "", m)
		// The body reaches the SANDBOXED WORKER through the content store and nowhere else (D72/ENG-1);
		// it never travels on the Event.
		store.Put(ev.GetEventId(), m.Body)

		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		dec, err := eng.Process(dctx, ev)
		if err != nil {
			log.Warn("smtp: message ACCEPTED because the pipeline could not decide — this is the "+
				"fail-open path, not a policy decision",
				slog.String("err", err.Error()), slog.String("flow", flowID))
			return false
		}
		blocked := dec.GetAction() != corev1.Action_ACTION_ALLOW
		if blocked {
			log.Info("smtp: message REFUSED at end-of-DATA",
				slog.String("action", dec.GetAction().String()), slog.String("flow", flowID))
		}
		return blocked
	}
}
