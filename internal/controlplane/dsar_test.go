package controlplane_test

import (
	"context"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// PLAT-8: a DSAR compiles what the platform holds about one pseudonymous subject across every
// subject-keyed store — audit entries, peer alerts, cases, and legal-hold status — and refuses a
// subjectless request (which would dump the whole store).
func TestSubjectAccessReport(t *testing.T) {
	pool := requireDB(t)
	srv := controlplane.New(pool)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)

	const subj = "dsar_subj"
	// The anchor epoch, referenced by every entry's key_epoch FK.
	if _, err := pool.Exec(ctx,
		`INSERT INTO key_epochs (idx, public_key) VALUES (0, '\x00') ON CONFLICT (idx) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	// Two audit entries for the subject (minimal chain columns).
	for i, ago := range []time.Duration{2 * time.Hour, 1 * time.Hour} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO audit_entries (sequence, appended_at, prev_hash, hash, sig, subject_id)
			 VALUES ($1,$2,'\x00','\x00','\x00',$3)`, int64(i+1), base.Add(-ago), subj); err != nil {
			t.Fatal(err)
		}
	}
	// An entry for a DIFFERENT subject, to prove the report is scoped.
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_entries (sequence, appended_at, prev_hash, hash, sig, subject_id)
		 VALUES (99,$1,'\x00','\x00','\x00','someone_else')`, base); err != nil {
		t.Fatal(err)
	}
	// Two peer alerts, the higher one critical.
	if _, err := pool.Exec(ctx,
		`INSERT INTO peer_alerts (subject_id, risk_score, context_version, agent_id) VALUES
		 ($1, 0.95, 'v1', 'agent-a'), ($1, 0.60, 'v1', 'agent-a')`, subj); err != nil {
		t.Fatal(err)
	}
	// A case, which also places a legal hold on the subject.
	if _, err := srv.OpenCase(ctx, subj, "operator:alice"); err != nil {
		t.Fatal(err)
	}

	rep, err := srv.SubjectAccessReport(ctx, subj)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SubjectID != subj {
		t.Errorf("subject = %q, want %q", rep.SubjectID, subj)
	}
	if rep.AuditEntries.Count != 2 {
		t.Errorf("audit entries = %d, want 2 (the other subject's entry must be excluded)", rep.AuditEntries.Count)
	}
	if rep.AuditEntries.FirstAt == nil || rep.AuditEntries.LastAt == nil || !rep.AuditEntries.LastAt.After(*rep.AuditEntries.FirstAt) {
		t.Errorf("audit span not populated/ordered: %+v", rep.AuditEntries)
	}
	if rep.PeerAlerts.Count != 2 {
		t.Errorf("peer alerts = %d, want 2", rep.PeerAlerts.Count)
	}
	if rep.PeerAlerts.MaxSeverity != controlplane.SeverityCritical {
		t.Errorf("max severity = %q, want critical (0.95)", rep.PeerAlerts.MaxSeverity)
	}
	if len(rep.Cases) != 1 || rep.Cases[0].SubjectID != subj {
		t.Errorf("cases = %+v, want one for the subject", rep.Cases)
	}
	if !rep.UnderLegalHold {
		t.Error("under_legal_hold = false, but opening a case placed a hold")
	}

	// A subject with nothing held reads empty, not an error.
	empty, err := srv.SubjectAccessReport(ctx, "ghost_nobody")
	if err != nil {
		t.Fatal(err)
	}
	if empty.AuditEntries.Count != 0 || empty.PeerAlerts.Count != 0 || len(empty.Cases) != 0 || empty.UnderLegalHold {
		t.Errorf("empty subject report is not empty: %+v", empty)
	}
	if empty.AuditEntries.FirstAt != nil {
		t.Error("empty audit span should have nil bounds")
	}

	// A subjectless DSAR is refused.
	if _, err := srv.SubjectAccessReport(ctx, ""); err == nil {
		t.Error("a DSAR with no subject id must be refused")
	}
}
