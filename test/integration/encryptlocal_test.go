//go:build integration

package integration

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ENCRYPT_LOCAL, and getting the data back (D318).
//
// This is the enforcer with the sharpest consequence in the product: it makes a user's file unreadable in
// place. D293 found that the ENCRYPTING half shipped and NOTHING COULD DECRYPT — `Decrypt` carried the
// comment "exported because operator recovery is a real operation" and had no caller. Enabling the
// feature therefore destroyed data, from the point of view of the person whose file it was, and the
// recovery command was written to fix exactly that.
//
// AND THEN NOTHING EXERCISED EITHER HALF against a running engine. `OPENSHIELD_ENCRYPT_KEY` and
// `OPENSHIELD_ENCRYPT_PUBKEY` were both uncovered, so what was proven was that a package can encrypt and
// a command can decrypt — not that the file the shipped engine produces is the file the shipped recovery
// tool accepts. Those are different claims, and the gap between them is where a format or mode mismatch
// lives: it would surface for the first time on the day an operator actually needed the data.
//
// So these scenarios drive the REAL ENGINE to encrypt a REAL FILE and then recover it with the REAL
// COMMAND, in both modes.

// alertOnSecret is a policy that encrypts anything the classifier flags.
//
// ENCRYPT_LOCAL rather than QUARANTINE_LOCAL because it is the irreversible-looking one: quarantine moves
// a file, which any operator can undo with mv. Encryption cannot be undone without the key, which is what
// makes the recovery path load-bearing rather than a convenience.
const encryptOnHit = `package openshield
import rego.v1
hit if { some h in input.classification; h.confidence > 0.5 }
decision := {"action":"ENCRYPT_LOCAL","reason":"sensitive content","confidence":0.9} if { hit }
decision := {"action":"ALLOW","reason":"clean"} if { not hit }`

// A CPF that passes the check-digit validator, so the classifier genuinely fires rather than the test
// asserting against a detector that matches anything.
const seededCPF = "529.982.247-25"

func writeRandomKey(t *testing.T, path string, n int) []byte {
	t.Helper()
	key := make([]byte, n)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

// startEncryptingEngine runs an engine that enforces ENCRYPT_LOCAL over a watched directory.
func startEncryptingEngine(t *testing.T, stack *Stack, watch string, extra ...string) *Process {
	t.Helper()
	work := t.TempDir()
	policy := filepath.Join(work, "encrypt.rego")
	if err := os.WriteFile(policy, []byte(encryptOnHit), 0o600); err != nil {
		t.Fatal(err)
	}
	eng := Start(t, "openshield-engine", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_WATCH_DIRS=" + watch,
		"OPENSHIELD_POLICY_CUSTOM=" + policy,
		"OPENSHIELD_ENFORCE=1",
	}, extra...))
	eng.WaitForOutput("engine observing", 90*time.Second)
	return eng
}

// waitEncrypted waits for the engine to replace the file's contents with an OpenShield blob.
//
// It asserts on the MAGIC HEADER rather than on "the plaintext is gone", because a truncated or deleted
// file would also lack the plaintext — and would be an enforcement that destroyed the data instead of
// containing it, which is the failure this whole area is about.
func waitEncrypted(t *testing.T, path, wantMagic string) []byte {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		blob, err := os.ReadFile(path)
		if err == nil && strings.HasPrefix(string(blob), wantMagic) {
			return blob
		}
		time.Sleep(500 * time.Millisecond)
	}
	blob, _ := os.ReadFile(path)
	t.Fatalf("%s never became a %s blob (it is %d bytes starting %q)",
		path, wantMagic, len(blob), firstBytes(blob, 16))
	return nil
}

func firstBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

// TestASymmetricallyEncryptedFileIsRecoverable is the whole point: containment that can be reversed.
func TestASymmetricallyEncryptedFileIsRecoverable(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	watch, work := t.TempDir(), t.TempDir()
	keyPath := filepath.Join(work, "encrypt.key")
	writeRandomKey(t, keyPath, 32)

	eng := startEncryptingEngine(t, stack, watch, "OPENSHIELD_ENCRYPT_KEY="+keyPath)

	target := filepath.Join(watch, "payroll.txt")
	plaintext := "employee CPF " + seededCPF + "\n"
	if err := os.WriteFile(target, []byte(plaintext), 0o600); err != nil {
		t.Fatal(err)
	}
	blob := waitEncrypted(t, target, "OSENC1\x00")
	if contains(string(blob), seededCPF) {
		t.Fatal("the encrypted blob still contains the plaintext CPF — the file was not actually encrypted")
	}
	_ = eng

	// RECOVERY, with the shipped command and the endpoint's key.
	out := filepath.Join(work, "recovered.txt")
	if o, err := runCapture(t, "openshield-provision", nil, "recover",
		"--in", target, "--out", out, "--key", keyPath); err != nil {
		t.Fatalf("recovering the file: %v\n%s", err, o)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the recovered file: %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("recovered %q, want %q. An enforcer that makes a file unreadable and a recovery tool "+
			"that cannot reproduce it exactly is data loss with extra steps", got, plaintext)
	}

	// THE CIPHERTEXT SURVIVES. Recovery writes elsewhere and never destroys the blob, because a failed
	// or half-written decrypt would otherwise leave neither the plaintext nor the only copy of the data.
	if after, rerr := os.ReadFile(target); rerr != nil || string(after) != string(blob) {
		t.Errorf("the encrypted blob was modified or removed by recovery (err=%v)", rerr)
	}
}

// TestRecoveryRefusesToOverwrite is the safety property that matters most when someone is under pressure.
//
// IT USES A GENUINELY RECOVERABLE BLOB, and the first version did not — which made it vacuous. It fed
// recovery a handcrafted `OSENC1\x00whatever`, so with the clobber check REMOVED the command still
// failed, at decryption, and wrote nothing; the existing file survived and the test passed. The mutation
// walked straight through.
//
// The blob has to be one that recovery would SUCCEED on, or "the file was not overwritten" is a
// statement about the ciphertext being invalid rather than about the guard. So the engine encrypts a
// real file first.
func TestRecoveryRefusesToOverwrite(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	watch, work := t.TempDir(), t.TempDir()
	keyPath := filepath.Join(work, "encrypt.key")
	writeRandomKey(t, keyPath, 32)

	startEncryptingEngine(t, stack, watch, "OPENSHIELD_ENCRYPT_KEY="+keyPath)
	target := filepath.Join(watch, "notes.txt")
	if err := os.WriteFile(target, []byte("CPF "+seededCPF+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitEncrypted(t, target, "OSENC1\x00")

	const precious = "something important\n"
	existing := filepath.Join(work, "existing.txt")
	if err := os.WriteFile(existing, []byte(precious), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runCapture(t, "openshield-provision", nil, "recover",
		"--in", target, "--out", existing, "--key", keyPath)
	if err == nil {
		t.Fatalf("recovery OVERWROTE an existing file:\n%s", out)
	}
	if got, rerr := os.ReadFile(existing); rerr != nil || string(got) != precious {
		t.Errorf("the existing file was modified despite the refusal: %q (err=%v). The check runs BEFORE "+
			"decryption on purpose, so a wrong --out is caught while everything is still recoverable",
			got, rerr)
	}
	// And the refusal must SAY the file exists, not fail as a generic write error.
	if !contains(out, "already exists") {
		t.Errorf("the refusal does not name the clobber as the reason:\n%s", out)
	}
}

// TestAnEscrowBlobCannotBeOpenedByTheEndpoint is the property escrow mode EXISTS for.
//
// In escrow mode the endpoint holds only a public key, so a machine that encrypts a file cannot read it
// back — which is the point: an attacker who owns the endpoint gains nothing from the containment. If
// the endpoint could decrypt, escrow mode would be symmetric mode with extra ceremony.
func TestAnEscrowBlobCannotBeOpenedByTheEndpoint(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	watch, work := t.TempDir(), t.TempDir()

	if o, err := runCapture(t, "openshield-provision", nil, "escrow-keygen", "--out", work); err != nil {
		t.Fatalf("escrow-keygen: %v\n%s", err, o)
	}
	pub := filepath.Join(work, "escrow-pub")
	priv := filepath.Join(work, "escrow-priv")

	startEncryptingEngine(t, stack, watch, "OPENSHIELD_ENCRYPT_PUBKEY="+pub)

	target := filepath.Join(watch, "contract.txt")
	plaintext := "client CPF " + seededCPF + "\n"
	if err := os.WriteFile(target, []byte(plaintext), 0o600); err != nil {
		t.Fatal(err)
	}
	waitEncrypted(t, target, "OSENCX1\x00")

	// 1. THE ENDPOINT'S OWN MATERIAL DOES NOT OPEN IT. Offering the public key as a symmetric key is the
	// mistake an operator would actually make, and the refusal must NAME the right key rather than
	// failing as a generic decryption error — which reads identically to "your key is wrong".
	out, err := runCapture(t, "openshield-provision", nil, "recover",
		"--in", target, "--out", filepath.Join(work, "wrong.txt"), "--key", pub)
	if err == nil {
		t.Fatalf("an ESCROW blob was opened with the endpoint's public key:\n%s", out)
	}
	if !contains(out, "ESCROW") {
		t.Errorf("the refusal does not say this is an escrow blob needing the off-endpoint keypair, so an "+
			"operator would go looking for a different symmetric key:\n%s", out)
	}

	// 2. THE OFF-ENDPOINT KEYPAIR DOES. Without this the test would pass against a build that could not
	// decrypt escrow blobs at all — which is precisely the state D293 found ENCRYPT_LOCAL in.
	recovered := filepath.Join(work, "recovered.txt")
	if o, rerr := runCapture(t, "openshield-provision", nil, "recover",
		"--in", target, "--out", recovered, "--escrow-pub", pub, "--escrow-priv", priv); rerr != nil {
		t.Fatalf("recovering an escrow blob with the escrow keypair: %v\n%s", rerr, o)
	}
	got, rerr := os.ReadFile(recovered)
	if rerr != nil {
		t.Fatalf("reading the recovered file: %v", rerr)
	}
	if string(got) != plaintext {
		t.Errorf("recovered %q, want %q", got, plaintext)
	}
}

// TestANonOpenShieldFileIsNotSilentlyMangled.
//
// Said plainly by the tool, because the alternative is an operator concluding their key is wrong and
// spending the incident looking for a different one.
func TestANonOpenShieldFileIsNotSilentlyMangled(t *testing.T) {
	work := t.TempDir()
	keyPath := filepath.Join(work, "encrypt.key")
	writeRandomKey(t, keyPath, 32)
	plain := filepath.Join(work, "ordinary.txt")
	if err := os.WriteFile(plain, []byte("just a file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCapture(t, "openshield-provision", nil, "recover",
		"--in", plain, "--out", filepath.Join(work, "out.txt"), "--key", keyPath)
	if err == nil {
		t.Fatalf("recovery accepted a file that is not OpenShield-encrypted:\n%s", out)
	}
	if !contains(out, "not OpenShield-encrypted") {
		t.Errorf("the refusal does not say the file was never encrypted by this product:\n%s", out)
	}
}
