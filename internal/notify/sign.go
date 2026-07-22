package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// SignatureHeader carries the HMAC of a signed webhook body (SIEM-8). The name and the
// "sha256=<hex>" value format follow the GitHub webhook convention so an off-the-shelf
// receiver library can verify it.
const SignatureHeader = "X-Openshield-Signature"

// TimestampHeader carries the unix timestamp the signature is bound to (SIEM-8b). The MAC
// covers "<ts>." + body, so a receiver can reject a stale replay by the timestamp — a
// signature over the body alone would validate a captured delivery forever.
const TimestampHeader = "X-Openshield-Timestamp"

// ReplayTolerance is the default freshness window a receiver allows between the signed
// timestamp and its own clock. Wide enough for normal skew, narrow enough to bound replay.
const ReplayTolerance = 5 * time.Minute

// Sign returns the signature for body at time ts under secret: "sha256=" + hex(HMAC-SHA256)
// over "<ts>." + body (SIEM-8b). Binding the timestamp into the signed payload is what lets a
// receiver reject a stale replay (see VerifySignature); a webhook URL is otherwise an
// unauthenticated open endpoint whose captured (body, sig) would replay indefinitely.
func Sign(secret []byte, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether sigHeader is a valid, FRESH signature of body under secret.
// It parses tsHeader, rejects a timestamp outside ±tolerance of now (stale or implausibly
// future — the replay defense) BEFORE the MAC check, then recomputes Sign(secret, ts, body)
// and compares CONSTANT-TIME (hmac.Equal) so a forger cannot recover the MAC via timing. A
// malformed/absent header returns false without leaking where it diverged.
func VerifySignature(secret, body []byte, tsHeader, sigHeader string, now time.Time, tolerance time.Duration) bool {
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	if d := now.Unix() - ts; d > int64(tolerance/time.Second) || d < -int64(tolerance/time.Second) {
		return false // stale or implausibly future — a replay outside the window
	}
	expected := Sign(secret, ts, body)
	return hmac.Equal([]byte(sigHeader), []byte(expected))
}
