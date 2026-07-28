//go:build integration

package integration

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// THE SIGNED IOC FEED (NIPS-2), through the running gateway.
//
// An unsigned feed means whatever can write that file decides what the gateway blocks — and, the quieter
// and better attack, what it does NOT: dropping the indicators that would have caught you leaves a
// gateway that looks healthy and is blind in exactly one direction.
//
// `OPENSHIELD_IOC_FEED_KEY` is the answer, and its contract has two halves that are easy to conflate:
// the signature is verified BEFORE the feed is parsed (the parser is the untrusted-input surface), and a
// bad signature refuses the WHOLE feed rather than loading the part that parsed. A half-applied feed is
// an attacker's best outcome.
//
// The gateway package tests cover the verification function. Nothing covered the SETTING: the key file
// being read, the `.sig` path being derived, and — the half only a running process can show — the
// gateway REFUSING TO START rather than continuing unarmed.

// signFeed writes a feed, its detached ed25519 signature, and the operator's public key, returning the
// feed path and the key path.
//
// The signature is raw bytes over the raw file, and the public key is the bare 32 bytes `LoadPublicKey`
// expects — no envelope, no encoding. Getting that wrong produces "public key is N bytes, want 32",
// which is a clearer failure than most.
func signFeed(t *testing.T, dir, body string) (feed, pub string, priv ed25519.PrivateKey) {
	t.Helper()
	pk, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	feed = filepath.Join(dir, "ioc.feed")
	if err := os.WriteFile(feed, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feed+".sig", ed25519.Sign(sk, []byte(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	pub = filepath.Join(dir, "operator.pub")
	if err := os.WriteFile(pub, pk, 0o600); err != nil {
		t.Fatal(err)
	}
	return feed, pub, sk
}

// iocOrigin starts an origin and returns its host (the indicator) and its address.
func iocOrigin(t *testing.T) (host string, origin *upstream) {
	t.Helper()
	origin = startUpstream(t)
	h, _, err := net.SplitHostPort(origin.addr)
	if err != nil {
		t.Fatal(err)
	}
	return h, origin
}

const blockOnThreatPolicy = `package openshield
import rego.v1
decision := {"action":"BLOCK","reason":"known-bad destination"} if { count(input.threat.matches) > 0 }
decision := {"action":"ALLOW","reason":"clean"} if { count(input.threat.matches) == 0 }`

// TestAVerifiedIocFeedArmsTheGateway is the positive half: with a key configured and a good signature,
// the feed is loaded and its indicators actually decide a flow.
//
// It matters that this asserts on ENFORCEMENT rather than on the "VERIFIED against the operator key" log
// line. A gateway that verified the signature and then armed itself with an EMPTY feed would print that
// line and forward every flow.
func TestAVerifiedIocFeedArmsTheGateway(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	host, origin := iocOrigin(t)
	feed, pub, _ := signFeed(t, work, "ip "+host+"\n")

	policy := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnThreatPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	gw, addr := startGateway(t, stack,
		"OPENSHIELD_IOC_FEED="+feed,
		"OPENSHIELD_IOC_FEED_KEY="+pub,
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")
	gw.WaitForOutput("VERIFIED against the operator key", 60*time.Second)

	resp, err := proxyClient(t, addr).Get("http://" + origin.addr + "/anything")
	if err != nil {
		t.Fatalf("proxying to the known-bad destination: %v\n%s", err, gw.Output())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a flow to an indicator from the VERIFIED feed returned %d, want 403 — the feed was "+
			"accepted and then armed nothing\n%s", resp.StatusCode, gw.Output())
	}
	if n := origin.hits.Load(); n != 0 {
		t.Errorf("the known-bad destination received %d request(s) — a 403 to the client is not "+
			"prevention if the flow went anyway", n)
	}
}

// TestATamperedIocFeedStopsTheGatewayStarting is the half that only a running process shows.
//
// The refusal must be a REFUSAL TO RUN, not a warning. A gateway that logged "bad signature" and carried
// on with no feed is the attack succeeding: the indicators that would have caught the intruder are gone,
// the process is healthy, and the console shows a gateway doing its job.
func TestATamperedIocFeedStopsTheGatewayStarting(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	host, _ := iocOrigin(t)
	feed, pub, _ := signFeed(t, work, "ip "+host+"\ndomain evil.example\n")

	// Flip a byte in the FEED, leaving the signature intact — a poisoned feed in transit.
	body, err := os.ReadFile(feed)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xFF
	if err := os.WriteFile(feed, body, 0o600); err != nil {
		t.Fatal(err)
	}

	out := refuseToStart(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "gw-signer.state"),
		"OPENSHIELD_IOC_FEED=" + feed,
		"OPENSHIELD_IOC_FEED_KEY=" + pub,
	})
	if !contains(out, "SIGNED IOC feed") {
		t.Errorf("the refusal does not name the signed feed, so it is indistinguishable from any other "+
			"startup failure:\n%s", out)
	}
}

// TestAnIocFeedSignedByTheWrongKeyIsRefused isolates the SIGNATURE from parseability.
//
// A tampered feed is both unverifiable and (usually) unparseable, so refusing it proves little on its
// own — a build with the signature check deleted still refuses it, at the parser. This feed is perfectly
// well-formed and correctly signed, by the wrong operator. Only the signature check can reject it.
func TestAnIocFeedSignedByTheWrongKeyIsRefused(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()

	// A well-formed feed signed by an ATTACKER, checked against the OPERATOR's key.
	feed := filepath.Join(work, "ioc.feed")
	const body = "domain evil.example\n"
	if err := os.WriteFile(feed, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, attackerKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feed+".sig", ed25519.Sign(attackerKey, []byte(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	operatorPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(work, "operator.pub")
	if err := os.WriteFile(pub, operatorPub, 0o600); err != nil {
		t.Fatal(err)
	}

	out := refuseToStart(t, "openshield-gateway", []string{
		"OPENSHIELD_DSN=" + stack.DSN,
		"OPENSHIELD_LISTEN=127.0.0.1:" + freePort(t),
		"OPENSHIELD_WORKER_BIN=" + Binary(t, "openshield-worker"),
		"OPENSHIELD_SIGNER_FILE=" + filepath.Join(work, "gw-signer.state"),
		"OPENSHIELD_IOC_FEED=" + feed,
		"OPENSHIELD_IOC_FEED_KEY=" + pub,
	})
	if !contains(out, "SIGNED IOC feed") {
		t.Errorf("the refusal does not name the signed feed:\n%s", out)
	}
}

// TestAnIocFeedHotReloadsAndSurvivesABadEdit covers OPENSHIELD_IOC_FEED_RELOAD.
//
// THE ORDER IS THE TEST, for the reason the CASB catalog scenario records: written the other way round —
// start blocking, break the file, assert still blocking — the last step is vacuous, because a reload that
// EMPTIED the feed also stops blocking. Starting from a feed that does NOT name the destination inverts
// every assertion into the direction an empty feed cannot satisfy.
func TestAnIocFeedHotReloadsAndSurvivesABadEdit(t *testing.T) {
	stack := StartStack(t)
	migrateStack(t, stack)
	work := t.TempDir()
	host, origin := iocOrigin(t)

	feed := filepath.Join(work, "ioc.feed")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(feed, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// 1. A feed that names something ELSE, so the destination is clean.
	write("domain unrelated.example\n")

	policy := filepath.Join(work, "block.rego")
	if err := os.WriteFile(policy, []byte(blockOnThreatPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	gw, addr := startGateway(t, stack,
		"OPENSHIELD_IOC_FEED="+feed,
		"OPENSHIELD_IOC_FEED_RELOAD=1s",
		"OPENSHIELD_POLICY_CUSTOM="+policy,
		"OPENSHIELD_ENFORCE=1")
	gw.WaitForOutput("IOC feed hot-reload enabled", 60*time.Second)

	get := func() int {
		t.Helper()
		resp, err := proxyClient(t, addr).Get("http://" + origin.addr + "/anything")
		if err != nil {
			t.Fatalf("proxying: %v\n%s", err, gw.Output())
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := get(); code != http.StatusOK {
		t.Fatalf("step 1: a destination in NO indicator returned %d, want 200\n%s", code, gw.Output())
	}

	// 2. The operator adds the destination. No restart.
	write("domain unrelated.example\nip " + host + "\n")
	gw.WaitForOutput("IOC feed reloaded", 60*time.Second)
	if code := get(); code != http.StatusForbidden {
		t.Fatalf("step 2: after the indicator was ADDED the flow returned %d, want 403. A feed that only "+
			"takes effect at restart means every new indicator waits for a maintenance window\n%s",
			code, gw.Output())
	}

	// 3. A typo. The running feed must survive it.
	write("this is not a feed line\n")
	gw.WaitForOutput("IOC feed reload failed", 60*time.Second)
	if code := get(); code != http.StatusForbidden {
		t.Fatalf("step 3: after a MALFORMED edit the flow returned %d, want 403 — the previous feed must "+
			"be kept. A parse error that empties the feed turns one operator typo into a silent, "+
			"fleet-wide loss of threat blocking\n%s", code, gw.Output())
	}
}
