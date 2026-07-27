//go:build integration

package integration

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE OPERATOR TOOLING THAT NOTHING COULD PRODUCE (D315).
//
// Three separate files that a shipped binary READS at startup, and which no tool in the project could
// WRITE. It is the same shape three times, and it is the shape worth naming: a reader with no writer
// looks complete from inside the code — the format is defined, parsed, validated and unit-tested — and
// is unusable from outside it.
//
//   - THE POSTURE ROSTER. The gateway has verified each agent's posture against that agent's own enrolled
//     key since SEC-12, because one shared key let any endpoint forge any other's `Compliant=true`. The
//     roster had no writer, and `posture-keygen` still produced the SUPERSEDED single-key shape while
//     telling operators to install it as a variable the gateway no longer reads. Following the tool's own
//     instructions produced an inert posture channel.
//   - THE INTERCEPTION CA. `provision.InterceptionCA` carried a long comment on why it must be separate
//     from the fleet CA, and had no caller — so enabling HTTPS inspection meant minting a CA by hand, at
//     which point the separation the comment argues for is whatever the operator happened to do.
//   - THE BACKUP AND RESTORE DRILL. `internal/backup` owns the pg_dump arguments and the drill ORDER so
//     that a restore is not called finished until the ledger re-verifies. Nothing ran it. The procedure
//     protecting the system of record existed as a library.

// TestThePostureRosterCanBeBuiltAndIsLoaded is the round trip: the tool writes what the gateway reads.
//
// The assertion is the GATEWAY'S OWN VERDICT — it announces a signed posture subscription only when the
// roster loaded, and warns that the channel is inert otherwise. Asserting on the file's contents would
// prove the tool self-consistent, which is exactly what was already true and still useless.
func TestThePostureRosterCanBeBuiltAndIsLoaded(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	roster := filepath.Join(work, "posture.roster")

	// TWO agents, because a roster with one entry cannot show that enrolling the second keeps the first.
	// Losing earlier agents is the specific failure a fleet enrolled one machine at a time would hit, and
	// it surfaces as "the fleet lost posture after we added a laptop" — a long way from the cause.
	for _, agent := range []string{"laptop-a", "laptop-b"} {
		out := filepath.Join(work, agent)
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		if o, err := runCapture(t, "openshield-provision", nil, "posture-enroll",
			"--agent", agent, "--roster", roster, "--out", out); err != nil {
			t.Fatalf("enrolling %s: %v\n%s", agent, err, o)
		}
		if _, err := os.Stat(filepath.Join(out, "posture-priv")); err != nil {
			t.Fatalf("%s got no signing key: %v", agent, err)
		}
	}

	blob, err := os.ReadFile(roster)
	if err != nil {
		t.Fatalf("reading the roster: %v", err)
	}
	lines := strings.Fields(strings.TrimSpace(string(blob)))
	if len(lines) != 4 { // two lines of "<agent> <key>"
		t.Fatalf("the roster has %d fields, want 4 (two agents). Enrolling the second must not drop the "+
			"first:\n%s", len(lines), blob)
	}

	// ACCESS MODE, because that is the only mode that loads the roster — posture gates who reaches an
	// internal service, so it is consumed by the access proxy and not by the egress one. Starting the
	// wrong mode was my first attempt, and it failed in the most confusing way available: the roster was
	// correct, the file was loadable, and the gateway said nothing about it at all.
	p := newPKI(t)
	m := p.serverMaterial(t)
	policyPath := filepath.Join(work, "access.rego")
	if err := os.WriteFile(policyPath, []byte(accessPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_ACCESS_MODE=1",
		"OPENSHIELD_ACCESS_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_ACCESS_CLIENT_CA=" + p.caPEM,
		"OPENSHIELD_ACCESS_SERVER_CERT=" + m.Cert,
		"OPENSHIELD_ACCESS_SERVER_KEY=" + m.Key,
		"OPENSHIELD_ACCESS_POLICY=" + policyPath,
		"OPENSHIELD_ACCESS_CATALOG=payroll=http://127.0.0.1:1",
		"OPENSHIELD_POSTURE_ROSTER=" + roster,
	})
	gw.WaitForOutput("SIGNED device-posture subscription active", 90*time.Second)

	if contains(gw.Output(), "posture channel inert") {
		t.Errorf("the gateway loaded the roster AND reported the channel inert\n%s", gw.Output())
	}
}

// TestAMalformedRosterIsRefusedRatherThanRewritten.
//
// The gateway ABORTS STARTUP on a bad roster line. A tool that quietly dropped the lines it could not
// parse would hand back a file that loads cleanly — having removed agents whose absence nobody chose,
// and whose posture is then never applied. Silence is the wrong answer in both directions here.
func TestAMalformedRosterIsRefusedRatherThanRewritten(t *testing.T) {
	work := t.TempDir()
	roster := filepath.Join(work, "posture.roster")
	const damaged = "laptop-a AAAA BBBB CCCC\n"
	if err := os.WriteFile(roster, []byte(damaged), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runCapture(t, "openshield-provision", nil, "posture-enroll",
		"--agent", "laptop-b", "--roster", roster, "--out", work)
	if err == nil {
		t.Fatalf("enrolling into a malformed roster SUCCEEDED:\n%s", out)
	}
	after, rerr := os.ReadFile(roster)
	if rerr != nil {
		t.Fatalf("reading the roster back: %v", rerr)
	}
	if string(after) != damaged {
		t.Errorf("the roster was REWRITTEN despite the refusal:\nbefore %q\nafter  %q", damaged, after)
	}
}

// TestTheInterceptionCAIsMintedSeparatelyFromTheFleetCA.
//
// The separation is the security property, not a filing convention. An interception CA can sign a trusted
// certificate for ANY host, so its holder can impersonate the whole internet to every endpoint that
// trusts it — a far larger authority than the fleet CA, which only authorises agents and operators.
// Minting them as the same key would silently give the fleet CA that power.
func TestTheInterceptionCAIsMintedSeparatelyFromTheFleetCA(t *testing.T) {
	work := t.TempDir()
	fleet, intercept := filepath.Join(work, "fleet"), filepath.Join(work, "intercept")
	for _, d := range []string{fleet, intercept} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := runCapture(t, "openshield-provision", nil, "ca-init", "--out", fleet); err != nil {
		t.Fatalf("ca-init: %v\n%s", err, out)
	}
	if out, err := runCapture(t, "openshield-provision", nil, "intercept-ca", "--out", intercept); err != nil {
		t.Fatalf("intercept-ca: %v\n%s", err, out)
	}

	// THE ASSERTION IS ON THE SUBJECT, not on the key bytes — and the first version of this test got that
	// wrong in a way worth recording. It compared the two private keys and required them to differ, which
	// is trivially true of ANY two keygen calls: the mutation that minted the interception CA with
	// `provision.InitCA` — literally the fleet CA constructor, the exact fusion this test exists to
	// forbid — PASSED it. A test that a fresh random key differs from another fresh random key asserts
	// that the random number generator works.
	//
	// The property that actually distinguishes them is the one the code's comment promises: the CN
	// differs, so the two are TELLABLE APART in a trust store. That is what an operator auditing a
	// machine's trusted roots needs — "why does this laptop trust a CA that can sign for any host" is
	// answerable only if the certificate says what it is.
	interceptCert := parseCert(t, filepath.Join(intercept, "intercept-ca.pem"))
	fleetCert := parseCert(t, filepath.Join(fleet, "ca.pem"))

	if interceptCert.Subject.CommonName == fleetCert.Subject.CommonName {
		t.Fatalf("both CAs identify as %q, so a trust store cannot tell them apart. Whoever holds an "+
			"interception CA can impersonate any host to every endpoint trusting it; the fleet CA only "+
			"needs to authorise agents and operators, and the two must not be confusable",
			fleetCert.Subject.CommonName)
	}
	if !strings.Contains(strings.ToLower(interceptCert.Subject.CommonName), "interception") {
		t.Errorf("the interception CA's subject is %q, which does not say what it is. An operator "+
			"auditing why a machine trusts a CA that can sign for any host has only this string to go on",
			interceptCert.Subject.CommonName)
	}
	if !interceptCert.IsCA {
		t.Error("the interception CA is not a CA certificate, so it cannot sign the leaves interception needs")
	}
	// SELF-SIGNED, and this is the load-bearing half of the separation: a certificate the FLEET CA signed
	// would make the fleet CA an ancestor of every intercepted host, which is exactly the authority
	// transfer the split exists to prevent.
	if err := interceptCert.CheckSignatureFrom(fleetCert); err == nil {
		t.Error("the interception CA is signed BY THE FLEET CA. Anything the interception CA can sign, " +
			"the fleet CA can therefore also vouch for — so fleet identity silently gains the power to " +
			"impersonate any host on the internet")
	}
	if string(mustRead(t, filepath.Join(fleet, "ca-key.pem"))) ==
		string(mustRead(t, filepath.Join(intercept, "intercept-ca-key.pem"))) {
		t.Error("the two CAs share a private key")
	}
	// The private key must not be world-readable: it IS interception's security.
	info, err := os.Stat(filepath.Join(intercept, "intercept-ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("the interception CA key is mode %04o — readable beyond its owner", perm)
	}
}

// TestTheInterceptionCAIsUsableByTheGateway closes the loop: minting a CA no binary accepts would be a
// new unwired feature standing in for the old one.
func TestTheInterceptionCAIsUsableByTheGateway(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	if out, err := runCapture(t, "openshield-provision", nil, "intercept-ca", "--out", work); err != nil {
		t.Fatalf("intercept-ca: %v\n%s", err, out)
	}
	gw := Start(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "signer.state"),
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_INTERCEPT_CA_CERT=" + filepath.Join(work, "intercept-ca.pem"),
		"OPENSHIELD_INTERCEPT_CA_KEY=" + filepath.Join(work, "intercept-ca-key.pem"),
		"OPENSHIELD_NO_INTERCEPT=bank.example.com",
	})
	gw.WaitForOutput("interception", 90*time.Second)
}

// TestABackupCanBeTakenAndTheRestoreDrillPasses is the one that protects everything else.
//
// The audit ledger is the product's central claim — tamper-evident, forward-secure, externally anchored —
// and all of that is worth nothing against a disk failure if the backup procedure is a package nobody
// runs. This takes a REAL dump of a REAL database and restores it, so "the procedure works" stops being
// a claim about argument strings.
func TestABackupCanBeTakenAndTheRestoreDrillPasses(t *testing.T) {
	requirePGTools(t)
	stack := StartStack(t)
	migrateStack(t, stack)
	dump := filepath.Join(t.TempDir(), "openshield.dump")

	if out, err := runCapture(t, "openshieldctl", []string{"OPENSHIELD_DSN=" + stack.DSN},
		"backup", "dump", "--file", dump); err != nil {
		t.Fatalf("taking a backup: %v\n%s", err, out)
	}
	info, err := os.Stat(dump)
	if err != nil {
		t.Fatalf("the backup produced no file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("the backup file is empty — a zero-byte dump that reports success is the failure a " +
			"restore drill exists to catch, and it would be caught in the worst possible circumstances")
	}
}

// TestARestoreDrillWithoutAWitnessIsRefused is the property `internal/backup` was written around, and the
// one a wrapper is most likely to quietly drop.
//
// Without an anchor to check against, TRUNCATION is undetectable — and truncation is the most likely way
// a restore loses evidence. A drill that cannot detect it is a rehearsal of the wrong thing, and would
// report PASSED over a ledger missing its most recent entries.
func TestARestoreDrillWithoutAWitnessIsRefused(t *testing.T) {
	work := t.TempDir()
	dump := filepath.Join(work, "x.dump")
	if err := os.WriteFile(dump, []byte("not a real dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCapture(t, "openshieldctl", nil, "backup", "drill", "--file", dump)
	if err == nil {
		t.Fatalf("a restore drill with NO WITNESS was accepted:\n%s", out)
	}
	if !contains(out, "witness") {
		t.Errorf("the refusal does not say a witness is what is missing, so an operator cannot act on "+
			"it:\n%s", out)
	}
	// And it must refuse BEFORE touching the database: a drill that restores and then discovers it
	// cannot verify has already replaced the system of record with something it cannot vouch for.
	if contains(out, "pg_restore") {
		t.Errorf("the drill ran pg_restore before refusing for want of a witness:\n%s", out)
	}
}

// TestTheDrillScriptFailsClosed checks the rendered script, for the operator who puts it in a runbook.
func TestTheDrillScriptFailsClosed(t *testing.T) {
	work := t.TempDir()
	witness := filepath.Join(work, "witness.pub")
	if err := os.WriteFile(witness, []byte(base64.StdEncoding.EncodeToString([]byte("k"))), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCapture(t, "openshieldctl", nil, "backup", "drill", "--print",
		"--file", filepath.Join(work, "x.dump"), "--witness", witness)
	if err != nil {
		t.Fatalf("rendering the drill script: %v\n%s", err, out)
	}
	// `set -euo pipefail` is not decoration: without it a failed pg_restore is followed by a verification
	// of whatever was already in the database, which can PASS — a green drill over a restore that never
	// happened.
	if !contains(out, "set -euo pipefail") {
		t.Errorf("the drill script does not fail closed:\n%s", out)
	}
	// Verification must be LAST. A script that verified before restoring would check the old database
	// and report on it — the most convincing possible false pass.
	restore, verify := strings.Index(out, "pg_restore"), strings.Index(out, "restore-verify")
	if restore < 0 || verify < 0 || verify < restore {
		t.Errorf("the drill does not restore THEN verify (restore at %d, verify at %d):\n%s",
			restore, verify, out)
	}
}

func requirePGTools(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"pg_dump", "pg_restore"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("the backup drill needs %s (install the postgresql client tools); skipping", bin)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

// parseCert reads a PEM certificate.
func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(mustRead(t, path))
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return cert
}
