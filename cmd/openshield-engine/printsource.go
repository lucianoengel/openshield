package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"

	"github.com/lucianoengel/openshield/internal/clipboard"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
	"github.com/lucianoengel/openshield/internal/printguard"
)

// printJobEvent builds a CONTENT-FREE print event (DLP-2b): the printer, the submitting user and the size.
//
// There is no title, deliberately — a document's title routinely IS the sensitive fact ("Q3 layoffs.docx"),
// so the contract records only whether one existed. The document itself goes to the sandboxed worker.
func printJobEvent(req printguard.Request) *corev1.Event {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &corev1.Event{
		EventId:     "print-" + hex.EncodeToString(b[:]),
		ConnectorId: "print",
		Kind:        corev1.EventKind_EVENT_KIND_PRINT_JOB,
		Purpose:     corev1.Purpose_PURPOSE_DLP,
		Target: &corev1.Event_Print{Print: &corev1.PrintSubject{
			Printer:         req.Printer,
			JobUser:         req.User,
			ByteCount:       uint32(len(req.Job)),
			JobTitlePresent: req.HasTitle,
		}},
	}
}

// printDecider answers the CUPS filter: classify the job through the real pipeline and deny when the
// decision is anything other than ALLOW.
//
// An evaluation ERROR is returned rather than converted into a verdict. The filter fails open on an error,
// which is what we want — but it must be able to tell "the policy allowed this" from "we could not decide",
// because laundering the second into the first would make an outage look like a clean bill of health.
func printDecider(ctx context.Context, eng processor, store *clipboard.ContentStore,
	events chan<- *corev1.Event, log *slog.Logger) func(context.Context, printguard.Request) (printguard.Verdict, error) {
	return func(rctx context.Context, req printguard.Request) (printguard.Verdict, error) {
		ev := printJobEvent(req)
		// The job bytes reach the classifier through the same content seam the clipboard uses, so the
		// engine forwards them to the sandboxed worker and never parses them here (D71/D29).
		store.Put(ev.GetEventId(), req.Job)
		select {
		case events <- ev:
		case <-rctx.Done():
			return printguard.VerdictAllow, rctx.Err()
		}
		dec, err := eng.Process(rctx, ev)
		if err != nil {
			return printguard.VerdictAllow, err
		}
		if dec.GetAction() != corev1.Action_ACTION_ALLOW {
			log.Warn("print: job REFUSED by policy",
				slog.String("printer", req.Printer), slog.String("user", req.User),
				slog.Int("bytes", len(req.Job)), slog.String("action", dec.GetAction().String()))
			return printguard.VerdictDeny, nil
		}
		return printguard.VerdictAllow, nil
	}
}

// processor is the slice of the engine this needs, so the decider is testable without a full engine.
type processor interface {
	Process(ctx context.Context, ev *corev1.Event) (*corev1.Decision, error)
}
