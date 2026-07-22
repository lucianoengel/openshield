package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// SIEM-8/8b: a body signed with a secret at a timestamp verifies under that same secret when fresh,
// and a tampered body, a wrong secret, a stale timestamp, or a swapped timestamp all fail — so a
// receiver trusts the alert came from this control plane, unaltered, and is not a replay.
func TestSignAndVerify(t *testing.T) {
	secret := []byte("s3cr3t")
	body := []byte(`{"kind":"peer-alert","subject":"sub_x"}`)
	now := time.Unix(1_700_000_000, 0)
	ts := now.Unix()
	tsHdr := strconv.FormatInt(ts, 10)
	sig := Sign(secret, ts, body)

	if !VerifySignature(secret, body, tsHdr, sig, now, ReplayTolerance) {
		t.Fatal("a correctly-signed fresh body did not verify")
	}
	if len(sig) < 7 || sig[:7] != "sha256=" {
		t.Errorf("signature %q is not sha256=<hex>", sig)
	}

	// Tampered body / wrong secret → fail.
	tampered := append([]byte{}, body...)
	tampered[0]++
	if VerifySignature(secret, tampered, tsHdr, sig, now, ReplayTolerance) {
		t.Error("a tampered body verified — integrity is not protected")
	}
	if VerifySignature([]byte("wrong"), body, tsHdr, sig, now, ReplayTolerance) {
		t.Error("a wrong secret verified — origin is not authenticated")
	}
	// Malformed headers rejected without panicking.
	if VerifySignature(secret, body, tsHdr, "", now, ReplayTolerance) ||
		VerifySignature(secret, body, "not-a-number", sig, now, ReplayTolerance) ||
		VerifySignature(secret, body, tsHdr, "sha256=zzzz", now, ReplayTolerance) {
		t.Error("a malformed or absent header verified")
	}

	// REPLAY: the exact captured (ts, body, sig) presented after the window → rejected, even though
	// the HMAC over the body still matches. This is the SIEM-8b defense.
	late := now.Add(ReplayTolerance + time.Minute)
	if VerifySignature(secret, body, tsHdr, sig, late, ReplayTolerance) {
		t.Error("a stale replay verified — the freshness window is not enforced")
	}
	// An implausibly-future timestamp (receiver clock well behind the signed ts) → rejected.
	early := now.Add(-(ReplayTolerance + time.Minute))
	if VerifySignature(secret, body, tsHdr, sig, early, ReplayTolerance) {
		t.Error("an implausibly-future timestamp verified")
	}
	// The timestamp is BOUND into the MAC: presenting a DIFFERENT (still-fresh) timestamp with the
	// original signature fails — otherwise an attacker could refresh a captured replay's timestamp.
	ts2 := strconv.FormatInt(now.Add(time.Minute).Unix(), 10)
	if VerifySignature(secret, body, ts2, sig, now, ReplayTolerance) {
		t.Error("a signature verified under a different timestamp — the timestamp is not bound into the MAC")
	}
}

// The webhook sends the signature + timestamp headers only when a secret is set; unsigned delivery is
// byte-for-byte unchanged, and a captured signed delivery does not replay past the window.
func TestWebhookSignsBodyWhenSecretSet(t *testing.T) {
	secret := []byte("hook-secret")
	var gotSig, gotTS string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(SignatureHeader)
		gotTS = r.Header.Get(TimestampHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fixed := time.Unix(1_700_000_000, 0)
	w := &Webhook{URL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}, Secret: secret,
		now: func() time.Time { return fixed }}
	n := Notification{Kind: KindPeerAlert, Subject: "sub_signed", At: fixed.UTC()}
	if err := w.Notify(context.Background(), n); err != nil {
		t.Fatalf("signed webhook delivery failed: %v", err)
	}
	if gotSig == "" || gotTS == "" {
		t.Fatalf("missing signature (%q) or timestamp (%q) header on a webhook with a secret", gotSig, gotTS)
	}
	if !VerifySignature(secret, gotBody, gotTS, gotSig, fixed, ReplayTolerance) {
		t.Error("the receiver could not verify the body it received against the headers")
	}
	// A captured delivery replayed after the window is rejected.
	if VerifySignature(secret, gotBody, gotTS, gotSig, fixed.Add(ReplayTolerance+time.Minute), ReplayTolerance) {
		t.Error("a captured signed delivery replays after the freshness window")
	}
	var decoded Notification
	if err := json.Unmarshal(gotBody, &decoded); err != nil || decoded.Subject != "sub_signed" {
		t.Errorf("signed body was not the notification JSON: %v / %+v", err, decoded)
	}

	// Unsigned webhook: no headers, byte-for-byte unchanged behavior.
	gotSig, gotTS = "unset", "unset"
	wu := &Webhook{URL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}}
	if err := wu.Notify(context.Background(), n); err != nil {
		t.Fatalf("unsigned webhook delivery failed: %v", err)
	}
	if gotSig != "" || gotTS != "" {
		t.Errorf("an unsigned webhook sent headers sig=%q ts=%q, want none", gotSig, gotTS)
	}
}
