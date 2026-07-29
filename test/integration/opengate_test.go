//go:build integration

package integration

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE ENGINE'S HALF OF THE FILE-OPEN GATE (B2), without root.
//
// The producer needs CAP_SYS_ADMIN and a permission-capable kernel, so it is verified on the VM. The
// ENGINE's half needs neither: it answers verdicts on a socket, from the real pipeline — the real
// sandboxed worker, the real policy, the real ledger. That is the half a deployment runs, and until
// now it was covered only by unit tests with a stubbed decider.
//
// WHAT THIS PROVES THAT THOSE CANNOT: that a gated decision reaches POSTGRES. D358 found that the gate
// refused opens and wrote nothing down — the synchronous tier set no audit sink, on the correct-sounding
// grounds that "the async engine owns the durable record", and for this gate no async engine exists. A
// unit test with a capturing ledger proves the seam is installed; only this proves the row lands in the
// system of record.

// openGateFrame builds a request frame for the open-verdict wire (magic "OSOG", version 1).
//
// Hand-rolled rather than imported, deliberately: encoding with the same code the engine decodes with
// would agree with itself whatever either does. A frame built from the format as DOCUMENTED catches a
// wire change that both sides adopted without anyone noticing the compatibility break.
func openGateFrame(id uint64, pid int32, path string, prefix []byte) []byte {
	const headerLen = 4 + 1 + 8 + 4 + 2 + 4
	buf := make([]byte, headerLen+len(path)+len(prefix))
	binary.BigEndian.PutUint32(buf[0:4], 0x4F534F47) // "OSOG"
	buf[4] = 1
	binary.BigEndian.PutUint64(buf[5:13], id)
	binary.BigEndian.PutUint32(buf[13:17], uint32(pid))
	binary.BigEndian.PutUint16(buf[17:19], uint16(len(path)))
	binary.BigEndian.PutUint32(buf[19:23], uint32(len(prefix)))
	copy(buf[headerLen:], path)
	copy(buf[headerLen+len(path):], prefix)
	return buf
}

// askOpenGate sends one question and returns the verdict byte.
func askOpenGate(t *testing.T, sock string, path string, prefix []byte) byte {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 15*time.Second)
	if err != nil {
		t.Fatalf("dialing the open-verdict socket: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write(openGateFrame(1, 4242, path, prefix)); err != nil {
		t.Fatal(err)
	}
	var resp [14]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("the engine answered a truncated frame — the wire format has changed on one side")
		}
		t.Fatalf("reading the verdict: %v", err)
	}
	if got := binary.BigEndian.Uint32(resp[0:4]); got != 0x4F534F47 {
		t.Fatalf("response magic %#08x — not the open-gate wire", got)
	}
	return resp[13]
}

// TestTheEngineAnswersOpenVerdictsAndRecordsThem.
func TestTheEngineAnswersOpenVerdictsAndRecordsThem(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	sock := filepath.Join(work, "open.sock")

	// A policy that BLOCKS a checksum-backed detection, so a denial is reachable at all. The default
	// policy alerts rather than blocks (D1 observe-only), and a gate that can only ever allow would let
	// every assertion below pass while refusing nothing.
	policyPath := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policyPath, []byte(blockOnStrongHit), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policyPath,
		"OPENSHIELD_OPEN_IPC_SOCKET=" + sock,
	})
	eng.WaitForOutput("open-verdict IPC ACTIVE", 90*time.Second)
	// The socket appears asynchronously as the server binds; waiting on the file is what makes the first
	// question a real one rather than a connection refused.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// THE WORKER POOL IS SIZED FOR THE GATE. D357: a single worker serialises every classification, so
	// enabling the gate without a pool silently undoes its concurrency. It is a pool of its OWN, not a
	// share of the classification pool — see TestAGatedOpenIsAlsoFullyClassified for why reservation
	// and capacity are different properties here.
	if !contains(eng.Output(), "gate worker pool") {
		t.Errorf("the engine did not start a worker pool for the open gate. One worker "+
			"serialises every classification, so concurrent gated opens would queue behind each "+
			"other\n%s", eng.Output())
	}

	pool := openPool(t, stack.DSN)
	entries := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t), `SELECT count(*) FROM audit_entries`).Scan(&n)
		return n
	}

	// 1. ORDINARY CONTENT IS ALLOWED. Without this, the denial below is satisfied by an engine that
	// refuses everything — which as a file-open gate is an outage, not a control.
	before := entries()
	if v := askOpenGate(t, sock, "/watched/notes.txt", []byte("an ordinary file with nothing of interest\n")); v != 0 {
		t.Errorf("ordinary content produced verdict %d, want 0 (allow)\n%s", v, eng.Output())
	}

	// 2. A CHECKSUM-BACKED CPF IS REFUSED — the content path ran, in the real worker.
	if v := askOpenGate(t, sock, "/watched/export.csv", []byte("name,cpf\nalice,111.444.777-35\n")); v != 1 {
		t.Errorf("a checksum-valid CPF produced verdict %d, want 1 (deny). The prefix reached the "+
			"worker, or it did not\n%s", v, eng.Output())
	}

	// 3. BOTH DECISIONS REACHED THE LEDGER. This is D358: the gate used to write nothing at all, so an
	// inline refusal left no evidence — the one decision an investigator most wants to review.
	//
	// The append is asynchronous by design (the ledger write must never sit inside a permission
	// window), so this waits rather than reading immediately.
	Eventually(t, 60*time.Second, "the gated decisions to reach the ledger", func() bool {
		return entries() >= before+2
	})

	// 4. AND THE LEDGER IS CONTENT-FREE. The prefix is attacker-controlled file content and the ledger
	// is the most copied, longest-retained artefact in the system (D10/D29).
	assertLedgerCarriesNone(t, stack, "111.444.777-35", "11144477735")
}

// TestAGatedOpenIsAlsoFullyClassified is the SECOND TIER (B2).
//
// The inline verdict comes from a bounded prefix — 16 KiB by the agent's default — so content past
// that ceiling is invisible to it. That is the design (D16: friction, not prevention), and until now
// it was the whole design: nothing classified the rest of the file, so a value at byte 20000 was
// neither refused inline nor detected afterwards.
//
// THE DETECTABLE VALUE IS PLACED PAST THE PREFIX ON PURPOSE, and the prefix handed to the gate is
// exactly the clean head. So the inline tier CANNOT have found it: an assertion that passes here is
// passing because the asynchronous tier read the whole file, and nothing else could have.
func TestAGatedOpenIsAlsoFullyClassified(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	sock := filepath.Join(work, "open.sock")

	// THE FILE LIVES OUTSIDE THE WATCHED DIRECTORY. If the watcher could see it, the watcher would
	// classify it on write and this test would pass with the async gate tier removed entirely — the
	// exact "green test that means nothing" shape this suite keeps finding.
	target := filepath.Join(work, "export.csv")
	const inlinePrefixBytes = 16 << 10 // the agent's OPENSHIELD_OPEN_PREFIX_BYTES default
	clean := bytes.Repeat([]byte("nothing of interest here\n"), 1+inlinePrefixBytes/25)
	if len(clean) < inlinePrefixBytes {
		t.Fatalf("the clean head is %d bytes, shorter than the %d-byte prefix — the CPF would be inside "+
			"the prefix and the inline tier could have found it", len(clean), inlinePrefixBytes)
	}
	body := append(append([]byte{}, clean...), []byte("name,cpf\nalice,111.444.777-35\n")...)
	if err := os.WriteFile(target, body, 0o644); err != nil {
		t.Fatal(err)
	}

	policyPath := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policyPath, []byte(blockOnStrongHit), 0o600); err != nil {
		t.Fatal(err)
	}

	eng := Start(t, "openshield-engine", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + t.TempDir(),
		"OPENSHIELD_POLICY_CUSTOM=" + policyPath,
		"OPENSHIELD_OPEN_IPC_SOCKET=" + sock,
	})
	eng.WaitForOutput("open-verdict IPC ACTIVE", 90*time.Second)

	// THE GATE'S WORKERS ARE RESERVED, not merely numerous. The async classification triggered by a
	// gated open itself opens the file, and that open is gated too — so a nested decision needs a
	// worker while the async work is holding one. Sharing a pool means the gate fails open under
	// exactly the load it caused.
	if !contains(eng.Output(), "gate worker pool") {
		t.Errorf("the engine did not start a SEPARATE worker pool for gate verdicts. Sharing the "+
			"classification pool means a nested gate decision waits for capacity the async tier is "+
			"using, so the gate times out and allows precisely when it is busiest\n%s", eng.Output())
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	pool := openPool(t, stack.DSN)
	asyncRows := func() int {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM audit_entries WHERE event_id = $1`, "opengate-"+target).Scan(&n)
		return n
	}

	// 1. THE INLINE VERDICT IS ALLOW. The prefix is clean, so it must be — and this is what makes the
	// detection below attributable to the async tier alone. A DENY here would mean the CPF was inside
	// the prefix after all, and the rest of the test would prove nothing.
	if v := askOpenGate(t, sock, target, body[:inlinePrefixBytes]); v != 0 {
		t.Fatalf("the inline verdict was %d for a CLEAN prefix. Either the prefix is not what was sent "+
			"or the policy fires on nothing; either way the async assertion below would be "+
			"unattributable\n%s", v, eng.Output())
	}

	// 2. THE WHOLE FILE WAS CLASSIFIED, and the classification found what the prefix could not — a
	// BLOCK (action 3) under a policy keyed on a checksum-backed detection.
	Eventually(t, 90*time.Second, "the async full-file classification of the gated open", func() bool {
		var n int
		_ = pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM audit_entries WHERE event_id = $1 AND action = 3`,
			"opengate-"+target).Scan(&n)
		return n >= 1
	})

	// 3. AND IT HAPPENED ONCE. Asking again inside the suppression window still gets a verdict — the
	// gate decides every open, always — but does not queue another full-file classification. That
	// suppression is the cycle breaker: in a real deployment the classifier's OWN open of this file is
	// one of these repeat questions, and resubmitting it is an unbounded loop.
	before := asyncRows()
	for i := 0; i < 3; i++ {
		if v := askOpenGate(t, sock, target, body[:inlinePrefixBytes]); v != 0 {
			t.Errorf("a repeat open produced verdict %d, want 0 — suppression must silence the "+
				"RE-CLASSIFICATION, never the verdict; a suppressed open that stops being decided is a "+
				"hole in the gate", v)
		}
	}
	// Long enough that a second classification would have landed. Asserting immediately would pass
	// against a suppressor that does nothing, simply by outrunning the queue.
	time.Sleep(10 * time.Second)
	if after := asyncRows(); after != before {
		t.Errorf("three repeat opens inside the suppression window produced %d more async "+
			"classifications (%d -> %d). Each one re-reads the whole file, and in a deployment each "+
			"one is itself a gated open — which is the loop", after-before, before, after)
	}

	// 4. THE FULL-FILE CLASSIFICATION IS CONTENT-FREE TOO. The async tier reads the WHOLE file, so it
	// holds far more than the inline tier ever did; the ledger must still carry none of it (D10/D29).
	assertLedgerCarriesNone(t, stack, "111.444.777-35", "11144477735")
}

// blockOnStrongHit refuses content carrying a checksum-backed detection. Keyed on the CLASSIFICATION
// rather than the path, so the decision can only change if the prefix actually reached the worker.
const blockOnStrongHit = `package openshield
import rego.v1
strong if { some h in input.classification; h.confidence >= 0.9 }
decision := {"action":"BLOCK","reason":"checksum-backed identifier in an opened file","confidence":0.95} if { strong }
decision := {"action":"ALLOW","reason":"nothing detected","confidence":0.5} if { not strong }`
