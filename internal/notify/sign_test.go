package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// SIEM-8: a body signed with a secret verifies under that same secret, and a tampered body or a
// wrong secret fails — so a receiver can trust the alert came from this control plane unaltered.
func TestSignAndVerify(t *testing.T) {
	secret := []byte("s3cr3t")
	body := []byte(`{"kind":"peer-alert","subject":"sub_x"}`)

	sig := Sign(secret, body)
	if !VerifySignature(secret, body, sig) {
		t.Fatal("a correctly-signed body did not verify")
	}
	// The signature format is the GitHub convention.
	if len(sig) < len("sha256=") || sig[:7] != "sha256=" {
		t.Errorf("signature %q is not sha256=<hex>", sig)
	}

	// A tampered body must not verify under the original signature.
	tampered := append([]byte{}, body...)
	tampered[0] = '{' + 1
	if VerifySignature(secret, tampered, sig) {
		t.Error("a tampered body verified — integrity is not protected")
	}
	// A wrong secret must not verify.
	if VerifySignature([]byte("wrong"), body, sig) {
		t.Error("a wrong secret verified — origin is not authenticated")
	}
	// A malformed/absent header is rejected without panicking.
	if VerifySignature(secret, body, "") || VerifySignature(secret, body, "sha256=zzzz") {
		t.Error("a malformed or absent header verified")
	}
}

// The webhook sends the signature header only when a secret is set; unsigned delivery is unchanged.
func TestWebhookSignsBodyWhenSecretSet(t *testing.T) {
	secret := []byte("hook-secret")
	var gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(SignatureHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Signed webhook: the receiver can verify the exact bytes it received.
	w := &Webhook{URL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}, Secret: secret}
	n := Notification{Kind: KindPeerAlert, Subject: "sub_signed", At: time.Unix(1700000000, 0).UTC()}
	if err := w.Notify(context.Background(), n); err != nil {
		t.Fatalf("signed webhook delivery failed: %v", err)
	}
	if gotSig == "" {
		t.Fatal("no signature header on a webhook configured with a secret")
	}
	if !VerifySignature(secret, gotBody, gotSig) {
		t.Error("the receiver could not verify the body it received against the header")
	}
	// Sanity: the signed body is the real notification JSON.
	var decoded Notification
	if err := json.Unmarshal(gotBody, &decoded); err != nil || decoded.Subject != "sub_signed" {
		t.Errorf("signed body was not the notification JSON: %v / %+v", err, decoded)
	}

	// Unsigned webhook: no header, byte-for-byte unchanged behavior.
	gotSig = "unset"
	wu := &Webhook{URL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}}
	if err := wu.Notify(context.Background(), n); err != nil {
		t.Fatalf("unsigned webhook delivery failed: %v", err)
	}
	if gotSig != "" {
		t.Errorf("an unsigned webhook sent a signature header %q, want none", gotSig)
	}
}
