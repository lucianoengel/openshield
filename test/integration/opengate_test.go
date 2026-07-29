//go:build integration

package integration

import (
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
	// enabling the gate without a pool silently undoes its concurrency.
	if !contains(eng.Output(), "worker pool") {
		t.Errorf("the engine did not start a worker pool with the open gate enabled. One worker "+
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

// blockOnStrongHit refuses content carrying a checksum-backed detection. Keyed on the CLASSIFICATION
// rather than the path, so the decision can only change if the prefix actually reached the worker.
const blockOnStrongHit = `package openshield
import rego.v1
strong if { some h in input.classification; h.confidence >= 0.9 }
decision := {"action":"BLOCK","reason":"checksum-backed identifier in an opened file","confidence":0.95} if { strong }
decision := {"action":"ALLOW","reason":"nothing detected","confidence":0.5} if { not strong }`
