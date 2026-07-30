// Package objectstore discovers sensitive data AT REST in an S3-compatible object store (DSPM-1).
//
// Every other producer in this tree is PUSHED: the kernel, a socket or a listener hands it something and it
// reacts. This one PULLS — it enumerates a bucket on a schedule and reads what it finds. That is a
// genuinely different producer shape, and it is the strongest test the D26/D69 fitness claim has had.
//
// # WHAT IT DOES NOT DO
//
// It does not classify. It reads a bounded prefix of each object and hands the bytes to the engine's
// content store, so the SANDBOXED WORKER is what parses them (D72) — object content is attacker-influenced
// the moment anyone can write to the bucket, and the process holding credentials and a network socket must
// not be the process parsing it (D13). The Event carries bucket and key and no content (D10/D29).
//
// It does not remediate. No delete, no move, no ACL change, no bucket mutation of any kind. Read-only.
//
// It does not tell you who can REACH the data. "Where is my sensitive data" and "who can get at it" are two
// features; this is the first, and implying the second would be the overclaiming the doc guard exists to
// prevent.
//
// # WHY NO SDK
//
// go.mod carries twelve direct dependencies and has clearly been defended. aws-sdk-go-v2 is dozens of
// modules to call two REST endpoints — ListObjectsV2 and a ranged GetObject — that are plain HTTP with an
// XML response. The only non-trivial part is SigV4, which is an HMAC-SHA256 chain the standard library
// already provides.
//
// The trade is stated rather than assumed: hand-rolled signing is fiddly and easy to get subtly wrong. The
// failure mode is benign — a wrong signature is a 403, because we are the client authenticating OURSELVES,
// not a check we are performing on somebody else — and it is caught immediately by testing against a real
// server rather than a mock that would agree with whatever this code believes.
//
// Speaking the S3 API rather than using the AWS SDK also means MinIO, Ceph, Wasabi, Backblaze and R2 work
// unchanged, which for a self-hostable product is arguably the more relevant target than AWS itself.
package objectstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// emptyPayloadSHA256 is SHA256(""), the payload hash for a request with no body. S3 requires
// x-amz-content-sha256 on every signed request, so this is not optional the way it is in some services.
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const (
	algorithm  = "AWS4-HMAC-SHA256"
	terminator = "aws4_request"
	service    = "s3"
)

// Credentials are the access key pair. Kept as a struct so a future session-token (STS) field is additive,
// and so nothing here takes two bare strings that are easy to transpose.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// signV4 signs an HTTP request in place with AWS Signature Version 4.
//
// The request must already carry its final URL and any headers that matter, because the signature commits
// to them: adding a header after signing invalidates it if that header is in SignedHeaders, and silently
// does nothing if it is not. Both are confusing to debug, so signing is the last step before the send.
func signV4(req *http.Request, creds Credentials, region string, payloadHash string, now time.Time) {
	if payloadHash == "" {
		payloadHash = emptyPayloadSHA256
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	signed, canonicalHeaders := canonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signed,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, terminator}, "/")
	stringToSign := strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		hex.EncodeToString(sha256sum([]byte(canonicalRequest))),
	}, "\n")

	// The signing key is derived per day/region/service, which is what makes a leaked signature useless
	// beyond its scope.
	k := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), dateStamp)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, terminator)
	signature := hex.EncodeToString(hmacSHA256(k, stringToSign))

	req.Header.Set("Authorization", algorithm+
		" Credential="+creds.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+
		", Signature="+signature)
}

// canonicalHeaders returns the semicolon-joined signed header names and the canonical header block.
//
// Host is included explicitly because Go keeps it on req.Host rather than in req.Header, and a signature
// that omits it is rejected — a failure that reads as a credentials problem and is not one.
func canonicalHeaders(req *http.Request) (signed string, block string) {
	names := []string{"host"}
	values := map[string]string{"host": req.Host}
	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		// Sign only what we must: the x-amz-* set plus Range, which changes WHAT IS RETURNED and so must
		// be covered or a proxy could rewrite it. Signing every header makes the request brittle against
		// anything that adds one in transit.
		if !strings.HasPrefix(lower, "x-amz-") && lower != "range" {
			continue
		}
		names = append(names, lower)
		values[lower] = strings.TrimSpace(strings.Join(vs, ","))
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteString(":")
		b.WriteString(values[n])
		b.WriteString("\n")
	}
	return strings.Join(names, ";"), b.String()
}

// canonicalURI encodes the path per RFC 3986, keeping "/" as a separator.
//
// PATH-STYLE ADDRESSING (endpoint/bucket/key) rather than virtual-host style (bucket.endpoint/key), because
// path-style is what MinIO and most S3-compatible servers use by default and works against a bare IP or a
// hostname without wildcard DNS. AWS still accepts it for this API.
func canonicalURI(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	segments := strings.Split(u.Path, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery sorts and encodes the query string. Sorting is required by the signature, not cosmetic —
// two orderings of the same parameters produce two different signatures.
func canonicalQuery(u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string{}, q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncode is RFC 3986 percent-encoding. net/url is deliberately NOT used: url.QueryEscape encodes a space
// as "+" and leaves some characters AWS expects encoded, either of which produces a signature mismatch that
// looks like a credentials failure.
func uriEncode(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%")
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
