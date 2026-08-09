package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lucianoengel/openshield/internal/retain"
)

// ApprovalExpiryFailures counts expiry sweeps that errored. A maintenance loop that has silently
// stopped running looks exactly like one with nothing to do.
var ApprovalExpiryFailures atomic.Int64

// readAllString reads a bounded body.
func readAllString(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	return string(b), err
}

// The OPERATOR SURFACE for cases and approvals (D290).
//
// Everything below already existed and was tested — `OpenCase`, `AssignCase`, `AddNote`,
// `RequestClose`, `ApproveClose`, `ReleaseLegalHold`, `ResolveApproval` — and none of it had a caller
// anywhere in the product. A playbook could open a case; a human could not. The four-eyes case closure,
// which is the control that stops one operator from closing their own investigation, could not be
// exercised at all: nothing could request a close, and nothing could approve one.
//
// That is the D287 shape, and the audit in docs/unwired-audit.md found it repeated across forty-six
// action paths. This closes the case-and-approval group.
//
// THE OPERATOR IS THE CLIENT CERTIFICATE, NEVER A REQUEST FIELD (D56). Every write here is an
// accountable act, and four-eyes is arithmetic on identities: if a caller could name themselves, the
// requester and the approver would be whoever the caller says they are, and the control would be
// decoration. An unattributable request is refused rather than recorded as anonymous.

// caseWriteHandlers mounts the case and approval operator routes.
//
// Split from operator_read.go because these are WRITES: they mount behind a higher role tier, and
// keeping the read surface and the act surface in one file is how a route ends up on the wrong one.
func (s *Server) caseWriteHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/cases", s.casesHandler)
	mux.HandleFunc("/cases/open", s.caseOpenHandler)
	mux.HandleFunc("/cases/assign", s.caseAssignHandler)
	mux.HandleFunc("/cases/note", s.caseNoteHandler)
	mux.HandleFunc("/cases/close/request", s.caseCloseRequestHandler)
	mux.HandleFunc("/cases/close/approve", s.caseCloseApproveHandler)
	mux.HandleFunc("/cases/hold/release", s.holdReleaseHandler)
	mux.HandleFunc("/approvals", s.approvalsHandler)
	mux.HandleFunc("/approvals/resolve", s.approvalResolveHandler)
}

// actor extracts the verified operator identity, or writes the refusal and reports false.
func actor(w http.ResponseWriter, r *http.Request, method string) (string, bool) {
	if r.Method != method {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	op := operatorIdentity(r.Context())
	if op == "" {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return "", false
	}
	return op, true
}

// int64Param reads a required numeric query parameter.
//
// A missing or malformed id is a 400 rather than a default, for the SEC-8 reason a malformed
// correlation window is: a silently-defaulted id would act on some OTHER case than the one asked for,
// which is worse than refusing.
func int64Param(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	v, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get(name)), 10, 64)
	if err != nil {
		http.Error(w, "bad "+name+": want an integer", http.StatusBadRequest)
		return 0, false
	}
	return v, true
}

// caseError maps a domain error to a status. ErrFourEyes is 403, not 400: the request is well-formed
// and the caller is authenticated — they are simply not allowed to be both requester and approver, and
// an operator reading a 400 would go looking for a typo.
func caseError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrFourEyes):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, pgx.ErrNoRows):
		http.Error(w, "no such case", http.StatusNotFound)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// casesHandler serves GET /cases?id=N — the case and its notes, the investigation trail an operator
// reads before acting on it.
func (s *Server) casesHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodGet)
	if !ok {
		return
	}
	id, ok := int64Param(w, r, "id")
	if !ok {
		return
	}
	c, err := s.GetCase(r.Context(), id)
	if err != nil {
		caseError(w, err)
		return
	}
	notes, err := s.CaseNotes(r.Context(), id)
	if err != nil {
		caseError(w, err)
		return
	}
	// D20: WHO VIEWED an investigation is auditable, not only who acted on one. Recorded before the
	// evidence is returned, which is the View invariant — a read that fails to record must not have
	// happened.
	if err := s.recordRequestView(r, ViewRecord{Viewer: op, SubjectFilter: c.SubjectID}); err != nil {
		http.Error(w, "recording the view failed; refusing to return the investigation", http.StatusInternalServerError)
		return
	}
	writeJSON(w, struct {
		Case  *Case      `json:"case"`
		Notes []CaseNote `json:"notes"`
	}{c, notes})
}

func (s *Server) caseOpenHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	id, err := s.OpenCase(r.Context(), subject, op)
	if err != nil {
		caseError(w, err)
		return
	}
	writeJSON(w, map[string]any{"case_id": id, "opened_by": op})
}

func (s *Server) caseAssignHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	id, ok := int64Param(w, r, "id")
	if !ok {
		return
	}
	assignee := strings.TrimSpace(r.URL.Query().Get("to"))
	if assignee == "" {
		http.Error(w, "to is required", http.StatusBadRequest)
		return
	}
	if err := s.AssignCase(r.Context(), id, assignee); err != nil {
		caseError(w, err)
		return
	}
	writeJSON(w, map[string]any{"case_id": id, "assigned_to": assignee})
}

func (s *Server) caseNoteHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	id, ok := int64Param(w, r, "id")
	if !ok {
		return
	}
	// The note is the BODY, not a query parameter: an investigation note is prose, and prose in a URL
	// is truncated by proxies and logged by everything in the path.
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	note, err := readAllString(body)
	if err != nil {
		http.Error(w, "reading the note: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(note) == "" {
		http.Error(w, "an empty note records nothing", http.StatusBadRequest)
		return
	}
	if err := s.AddNote(r.Context(), id, op, note); err != nil {
		caseError(w, err)
		return
	}
	writeJSON(w, map[string]any{"case_id": id, "author": op})
}

// caseCloseRequestHandler is the FIRST half of the four-eyes closure. It does not close anything.
func (s *Server) caseCloseRequestHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	id, ok := int64Param(w, r, "id")
	if !ok {
		return
	}
	if err := s.RequestClose(r.Context(), id, op); err != nil {
		caseError(w, err)
		return
	}
	writeJSON(w, map[string]any{"case_id": id, "close_requested_by": op,
		"note": "a SECOND operator must approve; the requester cannot"})
}

// caseCloseApproveHandler is the SECOND half, and refuses the requester.
func (s *Server) caseCloseApproveHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	id, ok := int64Param(w, r, "id")
	if !ok {
		return
	}
	if err := s.ApproveClose(r.Context(), id, op); err != nil {
		caseError(w, err)
		return
	}
	writeJSON(w, map[string]any{"case_id": id, "closed_by": op})
}

// holdReleaseHandler releases a subject's legal hold.
//
// Deliberately its own route rather than a side effect of closing a case: a hold outliving its case is
// a legitimate state (an investigation ends, the retention obligation does not), and releasing evidence
// from a hold is an act that should be asked for rather than inferred.
func (s *Server) holdReleaseHandler(w http.ResponseWriter, r *http.Request) {
	_, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		http.Error(w, "subject is required", http.StatusBadRequest)
		return
	}
	if err := s.ReleaseLegalHold(r.Context(), subject); err != nil {
		caseError(w, err)
		return
	}
	writeJSON(w, map[string]any{"subject_id": subject, "held": false})
}

// approvalsHandler serves GET /approvals — the pending four-eyes queue.
func (s *Server) approvalsHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := actor(w, r, http.MethodGet); !ok {
		return
	}
	rows, err := s.pool.Query(r.Context(),
		`SELECT id, subject_kind, subject_id, state, requester, coalesce(approver,''), reason,
		        requested_at, resolved_at, expires_at
		   FROM approvals WHERE state = 'pending' AND expires_at > now() ORDER BY id`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.SubjectKind, &a.SubjectID, &a.State, &a.Requester, &a.Approver,
			&a.Reason, &a.RequestedAt, &a.ResolvedAt, &a.ExpiresAt); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// approvalResolveHandler serves POST /approvals/resolve?id=N&approve=true|false.
//
// `approve` is REQUIRED and has no default. A defaulted approval decision is the one field in this
// package where a typo must never be resolved in either direction on the caller's behalf.
func (s *Server) approvalResolveHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := actor(w, r, http.MethodPost)
	if !ok {
		return
	}
	id, ok := int64Param(w, r, "id")
	if !ok {
		return
	}
	raw := r.URL.Query().Get("approve")
	approve, err := strconv.ParseBool(raw)
	if raw == "" || err != nil {
		http.Error(w, "approve is required and must be true or false", http.StatusBadRequest)
		return
	}
	if err := s.ResolveApproval(r.Context(), id, op, approve); err != nil {
		if errors.Is(err, ErrFourEyes) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"approval_id": id, "approved": approve, "resolved_by": op})
}

// RunApprovalExpiryLoop relabels timed-out approval requests on a timer.
//
// COSMETIC, AND SAID SO: expiry is already enforced in ResolveApproval's predicate, so a request past
// its deadline is unapprovable whether or not this loop has run. What it fixes is the QUEUE — an
// operator looking at a list of pending approvals should not see dead ones presented as live, because
// a queue full of things that cannot be actioned is a queue people stop reading.
//
// Leader-only, like the other maintenance loops: several replicas relabelling the same rows is
// harmless but pointless.
// It TAKES A LOGGER, which it did not before. This loop counted ApprovalExpiryFailures with no log call
// at all, so a failing sweep left a number and no explanation of it — and on a stop it left a number that
// was not even a failure. Both halves are now the shared helper's.
func (s *Server) RunApprovalExpiryLoop(ctx context.Context, interval func() time.Duration, log *slog.Logger) {
	retain.DynamicLoop(ctx, interval, func(c context.Context) {
		if _, err := s.ExpirePendingApprovals(c); err != nil {
			NoteTickErr(ctx, log, "approval expiry sweep failed", &ApprovalExpiryFailures, err)
		}
	})
}
