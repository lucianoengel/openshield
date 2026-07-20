package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/cli"
	"github.com/lucianoengel/openshield/internal/core"
	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// fakeReader stands in for the Postgres ledger. The CLI's contract — verify
// before render, never hide a break, distinguish exit codes — is independent of
// the storage, so it is tested here without a database.
type fakeReader struct {
	res     core.VerifyResult
	verErr  error
	entries []*core.Entry
	entErr  error
}

func (f *fakeReader) Verify(context.Context, ed25519.PublicKey) (core.VerifyResult, error) {
	return f.res, f.verErr
}
func (f *fakeReader) Entries(context.Context) ([]*core.Entry, error) {
	return f.entries, f.entErr
}

func ent(seq uint64, subject, event string, at time.Time) *core.Entry {
	return &core.Entry{
		Sequence: seq, SubjectID: subject, AppendedAt: at,
		Decision: &corev1.Decision{
			DecisionId: event, EventId: event, Action: corev1.Action_ACTION_ALERT, Confidence: 0.5,
		},
	}
}

func consistent(entries []*core.Entry) core.VerifyResult {
	return core.VerifyResult{
		Consistent: true, Completeness: core.CompletenessUnverified,
		Entries: len(entries), ToSequence: uint64(len(entries) - 1),
	}
}

// Task 3.3. A seeded incident renders in order and honours the subject filter.
func TestTimelineRendersOrdered(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	entries := []*core.Entry{
		ent(0, "alice", "e0", base),
		ent(1, "bob", "e1", base.Add(time.Minute)),
		ent(2, "alice", "e2", base.Add(2*time.Minute)),
	}
	r := &fakeReader{res: consistent(entries), entries: entries}

	var buf bytes.Buffer
	code := cli.Timeline(context.Background(), &buf, r, ed25519.PublicKey{1}, cli.Filter{Subject: "alice"})
	if code != cli.ExitOK {
		t.Fatalf("code = %d, want ExitOK", code)
	}
	out := buf.String()
	if !strings.Contains(out, "VERIFICATION: CONSISTENT") {
		t.Error("timeline rendered without a verification header")
	}
	if strings.Contains(out, "subject=bob") {
		t.Error("subject filter leaked bob into an alice timeline")
	}
	// alice's two entries, in order.
	i0 := strings.Index(out, "seq=0")
	i2 := strings.Index(out, "seq=2")
	if i0 < 0 || i2 < 0 || i0 > i2 {
		t.Errorf("entries not rendered in ascending sequence order:\n%s", out)
	}
}

// Task 3.3. A broken chain is named in the header and the tail is STILL printed
// and marked. Hiding the tail would deny an operator the tampered data they are
// investigating.
func TestTimelineNamesBreakAndPrintsTail(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	entries := []*core.Entry{
		ent(0, "alice", "e0", base),
		ent(1, "alice", "e1", base.Add(time.Minute)),
		ent(2, "alice", "e2", base.Add(2*time.Minute)),
	}
	brk := uint64(1)
	r := &fakeReader{
		res: core.VerifyResult{
			Consistent: false, Completeness: core.CompletenessUnverified,
			Entries: 3, ToSequence: 2, FirstBreak: &brk,
			Reason: "entry hash does not match its content: entry was modified",
		},
		entries: entries,
	}

	var buf bytes.Buffer
	code := cli.Timeline(context.Background(), &buf, r, nil, cli.Filter{})
	if code != cli.ExitInconsistent {
		t.Fatalf("code = %d, want ExitInconsistent", code)
	}
	out := buf.String()
	if !strings.Contains(out, "INCONSISTENT") || !strings.Contains(out, "FIRST BREAK at seq=1") {
		t.Errorf("header did not name the break:\n%s", out)
	}
	// The tail (seq 1 and 2) must still appear, marked.
	if !strings.Contains(out, "seq=2") {
		t.Error("the tail after the break was hidden — an operator cannot investigate what they cannot see")
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "seq=2") && !strings.Contains(line, "!!") {
			t.Errorf("post-break row not marked as suspect: %q", line)
		}
		if strings.Contains(line, "seq=0") && strings.Contains(line, "!!") {
			t.Errorf("pre-break row wrongly marked as suspect: %q", line)
		}
	}
}

// Task 3.4. The three outcomes a scheduler must tell apart have distinct codes.
func TestVerifyExitCodes(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	entries := []*core.Entry{ent(0, "alice", "e0", base)}
	brk := uint64(0)

	cases := []struct {
		name string
		r    *fakeReader
		want int
	}{
		{"consistent", &fakeReader{res: consistent(entries), entries: entries}, cli.ExitOK},
		{"tampered", &fakeReader{res: core.VerifyResult{Consistent: false, FirstBreak: &brk}}, cli.ExitInconsistent},
		{"unavailable", &fakeReader{verErr: core.ErrLedgerUnavailable}, cli.ExitUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if got := cli.Verify(context.Background(), &buf, c.r, nil); got != c.want {
				t.Errorf("exit = %d, want %d\n%s", got, c.want, buf.String())
			}
		})
	}
	// The distinctness itself is the contract: "cannot tell" must never equal
	// "tampered", or a cron job silences tamper alerts every time the DB blinks.
	if cli.ExitInconsistent == cli.ExitUnavailable {
		t.Fatal("inconsistent and unavailable share an exit code")
	}
}

// Task 3.5. The exported anchor states the limit of what it proves and is not
// described as independent proof.
func TestAnchorExportStatesItsLimit(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := cli.ExportAnchor(&buf, pub); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "-----BEGIN PUBLIC KEY-----") {
		t.Error("no PEM public key in the export")
	}
	if !strings.Contains(out, "OUT OF BAND") || !strings.Contains(strings.ToLower(out), "not independent proof") {
		t.Errorf("export does not state its trust limit:\n%s", out)
	}
}
