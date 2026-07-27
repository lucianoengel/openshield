//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE FOUR-EYES CASE CLOSURE, driven by two real operators over mutual TLS (D290).
//
// The control this exercises is the one that stops a single operator from closing their own
// investigation. Every piece of it existed and was tested — `RequestClose`, `ApproveClose`, the
// requester ≠ approver check — and until now NOTHING COULD REACH ANY OF IT. There was no route and no
// subcommand: a playbook could open a case, a human could not, and the closure control could not be
// exercised at all. `docs/unwired-audit.md` catalogues forty-five more of the same shape.
//
// IT MUST BE DRIVEN BY CERTIFICATES, not by request fields, and that is the whole reason this is an
// integration test rather than a handler test. Four-eyes is arithmetic on identities: if the caller
// could name themselves, requester and approver would be whoever the caller says they are and the
// control would be decoration. Only running the real server with real mutual TLS proves the identity
// the control compares is the one in the certificate.

// pki issues a CA and role-tagged operator certificates using the shipped provisioning tool.
//
// The real tool rather than a hand-rolled certificate, because the ROLE lives in the certificate's
// subject and how it is encoded is exactly the thing under test — a test that minted its own would be
// asserting against its own idea of the format.
type pki struct {
	dir, caPEM  string
	signingPriv string      // the control plane's ed25519 signing key, for deriving the public half
	tls         TLSMaterial // the server material, kept so a test can join the same mutually-authenticated broker
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := runCapture(t, "openshield-provision", nil, "ca-init", "--out", caDir); err != nil {
		t.Fatalf("ca-init: %v\n%s", err, out)
	}
	return &pki{dir: dir, caPEM: filepath.Join(caDir, "ca.pem")}
}

// operator issues a leaf certificate with the given role and common name, and returns an HTTP client
// that presents it.
func (p *pki) operator(t *testing.T, role, cn string) *http.Client {
	t.Helper()
	out := filepath.Join(p.dir, role+"-"+cn)
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if o, err := runCapture(t, "openshield-provision", nil, "cert",
		"--ca", filepath.Join(p.dir, "ca"), "--role", role, "--cn", cn,
		"--san", "127.0.0.1", "--out", out); err != nil {
		t.Fatalf("issuing %s/%s: %v\n%s", role, cn, err, o)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(out, "cert.pem"), filepath.Join(out, "key.pem"))
	if err != nil {
		t.Fatalf("loading %s/%s: %v", role, cn, err)
	}
	caPEM, err := os.ReadFile(p.caPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("the CA certificate did not parse")
	}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS12,
		}},
	}
}

// serverMaterial issues the control plane's own certificate.
func (p *pki) serverMaterial(t *testing.T) TLSMaterial {
	t.Helper()
	out := filepath.Join(p.dir, "server")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if o, err := runCapture(t, "openshield-provision", nil, "cert",
		"--ca", filepath.Join(p.dir, "ca"), "--role", "operator", "--cn", "control-plane",
		"--san", "127.0.0.1", "--san", "localhost", "--out", out); err != nil {
		t.Fatalf("issuing the server certificate: %v\n%s", err, o)
	}
	return TLSMaterial{CA: p.caPEM, Cert: filepath.Join(out, "cert.pem"), Key: filepath.Join(out, "key.pem")}
}

// tlsEnv is the process configuration for that material.
func tlsEnv(m TLSMaterial) []string {
	return []string{"OPENSHIELD_TLS_CA=" + m.CA, "OPENSHIELD_TLS_CERT=" + m.Cert, "OPENSHIELD_TLS_KEY=" + m.Key}
}

// mtlsServer starts a control plane whose HTTP surface AND broker connection are mutually
// authenticated against one CA, and returns its base URL.
func mtlsServer(t *testing.T, p *pki) (*Stack, *Process, string) {
	t.Helper()
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)
	addr := "127.0.0.1:" + freePort(t)
	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 90*time.Second)
	return stack, srv, "https://" + addr
}

// mtlsServerSigned is mtlsServer plus the ed25519 key the control plane signs risk, intents and fleet
// controls with — the one key OPENSHIELD_RISK_SIGNING_KEY has always been documented as covering.
func mtlsServerSigned(t *testing.T, p *pki) (*Stack, *Process, string) {
	t.Helper()
	m := p.serverMaterial(t)
	stack := StartStackTLS(t, m)
	migrateStack(t, stack)
	priv, _ := signingKeypair(t)
	p.signingPriv = priv
	addr := "127.0.0.1:" + freePort(t)
	srv := Start(t, "openshield-server", append([]string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_NATS_URL=" + stack.NATSURL,
		"OPENSHIELD_HTTP_ADDR=" + addr,
		"OPENSHIELD_RISK_SIGNING_KEY=" + priv,
	}, tlsEnv(m)...))
	waitTCP(t, addr, 90*time.Second)
	srv.WaitForOutput("signed risk, intent and fleet-control publishing", 60*time.Second)
	p.tls = m
	return stack, srv, "https://" + addr
}

// controlPlanePub writes the PUBLIC half of the signing key a consumer verifies intents and fleet
// controls against, and returns its path.
//
// Derived from the private key the server was given rather than generated separately, because a consumer
// holding an unrelated key rejects every message — which from outside is indistinguishable from a quiet
// channel, and would make this scenario pass while proving nothing.
func (p *pki) controlPlanePub(t *testing.T) string {
	t.Helper()
	priv, err := os.ReadFile(p.signingPriv)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(p.dir, "control-plane.pub")
	if err := os.WriteFile(out, ed25519.PrivateKey(priv).Public().(ed25519.PublicKey), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// do performs a request and returns the status and body.
func do(t *testing.T, c *http.Client, method, url string, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestFourEyesCaseClosureRefusesTheRequester is the whole point of the control.
func TestFourEyesCaseClosureRefusesTheRequester(t *testing.T) {
	p := newPKI(t)
	stack, srv, base := mtlsServer(t, p)

	alice := p.operator(t, "responder", "alice")
	bob := p.operator(t, "responder", "bob")

	// Alice opens a case. The subject comes from the query; the OPENER comes from her certificate.
	code, body := do(t, alice, http.MethodPost, base+"/cases/open?subject=subject-fourEyes", nil)
	if code != http.StatusOK {
		t.Fatalf("opening a case: %d %s\n%s", code, body, srv.Output())
	}
	var opened struct {
		CaseID   int64  `json:"case_id"`
		OpenedBy string `json:"opened_by"`
	}
	if err := json.Unmarshal([]byte(body), &opened); err != nil {
		t.Fatalf("parsing %q: %v", body, err)
	}
	if opened.OpenedBy != "operator:alice" {
		t.Errorf("the case was opened by %q — the opener must come from the CERTIFICATE, so that a "+
			"caller cannot record an act under someone else's name", opened.OpenedBy)
	}
	caseURL := fmt.Sprintf("%s/cases/close/request?id=%d", base, opened.CaseID)

	// Alice requests closure...
	if code, body = do(t, alice, http.MethodPost, caseURL, nil); code != http.StatusOK {
		t.Fatalf("requesting closure: %d %s\n%s", code, body, srv.Output())
	}

	// ...and cannot approve her own request. THIS IS THE CONTROL.
	//
	// It is enforced in TWO places, which the mutation round measured rather than assumed: the case
	// row's own `close_requested_by <> approver` predicate, and the APPROVAL object's `requester <>
	// approver`. Removing either alone leaves the refusal intact; only removing both lets Alice close
	// her own case. That is genuine defence in depth — and worth recording, because a single-site
	// mutation passing looks exactly like a test that does not work.
	approveURL := fmt.Sprintf("%s/cases/close/approve?id=%d", base, opened.CaseID)
	code, body = do(t, alice, http.MethodPost, approveURL, nil)
	if code != http.StatusForbidden {
		t.Fatalf("Alice approved HER OWN close request (%d %s). Four-eyes exists to stop exactly this, "+
			"and an investigation one person can open, close and approve is not an audited one\n%s",
			code, body, srv.Output())
	}

	// Bob can, and the case records HIM as the closer.
	if code, body = do(t, bob, http.MethodPost, approveURL, nil); code != http.StatusOK {
		t.Fatalf("Bob could not approve Alice's request: %d %s\n%s", code, body, srv.Output())
	}
	if !contains(body, "operator:bob") {
		t.Errorf("the closure does not name Bob: %s", body)
	}

	// And the stored case agrees — the response is the server's claim, the row is the record.
	pool := openPool(t, stack.DSN)
	var status, requestedBy, closedBy string
	if err := pool.QueryRow(Ctx(t),
		`SELECT status, coalesce(close_requested_by,''), coalesce(closed_by,'') FROM cases WHERE id=$1`,
		opened.CaseID).Scan(&status, &requestedBy, &closedBy); err != nil {
		t.Fatal(err)
	}
	if status != "closed" || requestedBy != "operator:alice" || closedBy != "operator:bob" {
		t.Errorf("case row is status=%q requested_by=%q closed_by=%q — the record must show BOTH pairs "+
			"of eyes, or the control leaves no evidence it was applied", status, requestedBy, closedBy)
	}
}

// TestAnAnalystCannotActOnACase pins the role tiers to the routes.
//
// Reading an investigation and acting on one are different authorities, and mounting a write route at
// the read tier is a one-character mistake that no unit test would notice.
func TestAnAnalystCannotActOnACase(t *testing.T) {
	p := newPKI(t)
	_, _, base := mtlsServer(t, p)

	analyst := p.operator(t, "analyst", "ana")
	responder := p.operator(t, "responder", "rita")

	// The analyst may READ the approval queue.
	if code, body := do(t, analyst, http.MethodGet, base+"/approvals", nil); code != http.StatusOK {
		t.Fatalf("an analyst cannot read the approval queue: %d %s", code, body)
	}
	// ...and may NOT open a case.
	if code, body := do(t, analyst, http.MethodPost, base+"/cases/open?subject=s1", nil); code != http.StatusForbidden {
		t.Errorf("an ANALYST opened a case (%d %s) — reading an investigation and acting on one are "+
			"different authorities", code, body)
	}
	// ...and may NOT release a legal hold, which is admin-only: it is the one operation here that makes
	// held evidence purgeable again.
	if code, body := do(t, responder, http.MethodPost, base+"/cases/hold/release?subject=s1", nil); code != http.StatusForbidden {
		t.Errorf("a RESPONDER released a legal hold (%d %s) — releasing evidence from a hold sits with "+
			"the admin tier, not with case management", code, body)
	}
}

// TestACaseNoteIsAttributedToItsAuthorAndTheReadIsRecorded covers the two properties that make a case
// an audit artifact rather than a text box.
func TestACaseNoteIsAttributedToItsAuthorAndTheReadIsRecorded(t *testing.T) {
	p := newPKI(t)
	stack, _, base := mtlsServer(t, p)
	carol := p.operator(t, "responder", "carol")

	_, body := do(t, carol, http.MethodPost, base+"/cases/open?subject=subject-notes", nil)
	var opened struct {
		CaseID int64 `json:"case_id"`
	}
	if err := json.Unmarshal([]byte(body), &opened); err != nil {
		t.Fatalf("parsing %q: %v", body, err)
	}
	const note = "checked the endpoint; the transfer was to a personal drive"
	if code, b := do(t, carol, http.MethodPost,
		fmt.Sprintf("%s/cases/note?id=%d", base, opened.CaseID), strings.NewReader(note)); code != http.StatusOK {
		t.Fatalf("adding a note: %d %s", code, b)
	}

	// READING the case records WHO looked (D20) — auditing who ACTED is not the same as auditing who
	// LOOKED, and an investigation surface that records only the former leaves the more common act
	// invisible.
	if code, b := do(t, carol, http.MethodGet,
		fmt.Sprintf("%s/cases?id=%d", base, opened.CaseID), nil); code != http.StatusOK {
		t.Fatalf("reading the case: %d %s", code, b)
	}
	pool := openPool(t, stack.DSN)
	var author, viewer string
	if err := pool.QueryRow(Ctx(t),
		`SELECT author FROM case_notes WHERE case_id=$1 AND note=$2`, opened.CaseID, note).
		Scan(&author); err != nil {
		t.Fatalf("the note was not stored: %v", err)
	}
	if author != "operator:carol" {
		t.Errorf("the note is attributed to %q, not the certificate that wrote it", author)
	}
	if err := pool.QueryRow(Ctx(t),
		`SELECT viewer FROM investigation_views WHERE subject_filter=$1 ORDER BY id DESC LIMIT 1`,
		"subject-notes").Scan(&viewer); err != nil {
		t.Fatalf("reading the case recorded no view: %v", err)
	}
	if viewer != "operator:carol" {
		t.Errorf("the view is recorded against %q", viewer)
	}
}
