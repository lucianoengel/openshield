package objectstore

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Defaults chosen so an unconfigured sweep is bounded and polite rather than unbounded and fast. Every one
// of them is a real limit on what the feature sees, which is why Sweep reports what it skipped.
const (
	// DefaultMaxObjects bounds one sweep. A bucket can hold ten million objects; a connector that
	// enumerates all of them never yields and never finishes.
	DefaultMaxObjects = 1000

	// DefaultMaxObjectBytes is the per-object prefix read via a ranged GET, so the ceiling costs no
	// bandwidth beyond it. Content past it is NOT examined — the same friction-not-guarantee position the
	// inline file gate takes (D16).
	DefaultMaxObjectBytes = 256 << 10

	// DefaultPageSize is the ListObjectsV2 page. The API's own ceiling is 1000.
	DefaultPageSize = 1000

	// DefaultTimeout bounds a single HTTP call. A store that accepts a connection and then never answers
	// must cost one request, not the sweep.
	DefaultTimeout = 30 * time.Second
)

// Config addresses one bucket in one S3-compatible store.
//
// Endpoint is a FULL URL because the store is not assumed to be AWS: MinIO on http://127.0.0.1:9000, a Ceph
// gateway, R2, Wasabi. The dev compose stack runs one; a production deployment points at whatever the
// operator already has. Nothing here defaults to an AWS hostname, because a discovery sweep that silently
// went to the wrong store would be worse than one that refused to start.
type Config struct {
	Endpoint string // e.g. "http://127.0.0.1:9000" or "https://s3.eu-west-1.amazonaws.com"
	Region   string // signing region; MinIO accepts anything, AWS does not
	Bucket   string
	Prefix   string // optional key prefix, so a sweep can be scoped to part of a bucket
	Creds    Credentials

	MaxObjects     int
	MaxObjectBytes int64
	PageSize       int

	HTTPClient *http.Client
	// Now is injectable so signing is testable against known-answer vectors. Nil means time.Now.
	Now func() time.Time
}

func (c *Config) applyDefaults() {
	if c.MaxObjects <= 0 {
		c.MaxObjects = DefaultMaxObjects
	}
	if c.MaxObjectBytes <= 0 {
		c.MaxObjectBytes = DefaultMaxObjectBytes
	}
	if c.PageSize <= 0 || c.PageSize > 1000 {
		c.PageSize = DefaultPageSize
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultTimeout}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Validate reports a configuration that cannot produce a meaningful sweep. Called before anything is
// started, so a misconfiguration is a refusal to run rather than a sweep that quietly finds nothing —
// "no sensitive data found" is the answer nobody re-checks, and it must never be produced by accident.
func (c *Config) Validate() error {
	switch {
	case strings.TrimSpace(c.Endpoint) == "":
		return fmt.Errorf("objectstore: no endpoint — set the full URL of the S3-compatible store")
	case strings.TrimSpace(c.Bucket) == "":
		return fmt.Errorf("objectstore: no bucket to sweep")
	case c.Creds.AccessKeyID == "" || c.Creds.SecretAccessKey == "":
		return fmt.Errorf("objectstore: no credentials — a sweep with none finds nothing and would report a clean bucket")
	}
	if _, err := url.Parse(c.Endpoint); err != nil {
		return fmt.Errorf("objectstore: endpoint %q is not a URL: %w", c.Endpoint, err)
	}
	return nil
}

// Object is one enumerated object. Size is the store's reported size, which is the FULL object — not how
// much of it was read.
type Object struct {
	Key  string
	Size int64
}

// Client talks to one bucket.
type Client struct {
	cfg Config
	// skipped counts objects enumerated but not examined because a bound was hit.
	skipped atomic.Int64
}

// New validates the configuration and returns a client.
func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return &Client{cfg: cfg}, nil
}

// Skipped reports how many objects a sweep enumerated but did not examine. NON-ZERO MEANS THE SWEEP WAS
// PARTIAL, and a caller that ignores it turns a partial sweep into a clean bill of health (D31).
func (c *Client) Skipped() int64 { return c.skipped.Load() }

// listResult mirrors the ListObjectsV2 XML response.
type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
}

// List enumerates up to MaxObjects objects, following pagination.
//
// It returns what it found AND records what it did not reach, rather than silently stopping at the ceiling.
func (c *Client) List(ctx context.Context) ([]Object, error) {
	// THE SKIP COUNT BELONGS TO THIS ENUMERATION, so it resets here. It was cumulative, and a test that
	// listed twice saw six skips over a five-object bucket — a coverage report that overstates what was
	// missed is a different lie from one that understates it, but it is still a lie, and this number exists
	// precisely so somebody can trust it.
	c.skipped.Store(0)
	var out []Object
	token := ""
	for {
		page, next, err := c.listPage(ctx, token)
		if err != nil {
			return out, err
		}
		for _, o := range page {
			if len(out) >= c.cfg.MaxObjects {
				// Enumerated but not returned: the caller must be able to see that the bucket held more.
				c.skipped.Add(1)
				continue
			}
			out = append(out, o)
		}
		if next == "" {
			return out, nil
		}
		if len(out) >= c.cfg.MaxObjects {
			// There are more pages and no room for them. Stop paginating, but do not pretend the bucket
			// ended here — the count above is what tells the truth, and a further page walk purely to
			// count would cost requests for a number nobody acts on differently.
			return out, nil
		}
		token = next
	}
}

func (c *Client) listPage(ctx context.Context, token string) ([]Object, string, error) {
	u, err := url.Parse(strings.TrimRight(c.cfg.Endpoint, "/") + "/" + c.cfg.Bucket)
	if err != nil {
		return nil, "", fmt.Errorf("objectstore: building the list URL: %w", err)
	}
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("max-keys", strconv.Itoa(c.cfg.PageSize))
	if c.cfg.Prefix != "" {
		q.Set("prefix", c.cfg.Prefix)
	}
	if token != "" {
		q.Set("continuation-token", token)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	signV4(req, c.cfg.Creds, c.cfg.Region, emptyPayloadSHA256, c.cfg.Now())

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("objectstore: listing %s: %w", c.cfg.Bucket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", statusErr("listing "+c.cfg.Bucket, resp)
	}
	// Bounded read: a store that streams an endless body must not exhaust this process.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, "", fmt.Errorf("objectstore: reading the list response: %w", err)
	}
	var lr listResult
	if err := xml.Unmarshal(body, &lr); err != nil {
		return nil, "", fmt.Errorf("objectstore: parsing the list response: %w", err)
	}
	objs := make([]Object, 0, len(lr.Contents))
	for _, ct := range lr.Contents {
		// A "directory" placeholder is a zero-byte key ending in "/". Nothing to classify.
		if ct.Size == 0 && strings.HasSuffix(ct.Key, "/") {
			continue
		}
		objs = append(objs, Object{Key: ct.Key, Size: ct.Size})
	}
	next := ""
	if lr.IsTruncated {
		next = lr.NextContinuationToken
	}
	return objs, next, nil
}

// Head reads a bounded PREFIX of one object via a ranged GET.
//
// Ranged rather than full: the ceiling has to cost no bandwidth beyond itself, or a sweep over a bucket of
// large objects is a bandwidth event on the operator's link. The returned bytes go to the content store for
// the sandboxed worker — this function never looks at them.
func (c *Client) Head(ctx context.Context, key string) ([]byte, error) {
	base := strings.TrimRight(c.cfg.Endpoint, "/") + "/" + c.cfg.Bucket + "/"
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("objectstore: building the object URL: %w", err)
	}
	// JoinPath escapes the key correctly, including keys with spaces or "+", which a naive concatenation
	// would corrupt into a different object or a signature mismatch.
	u = u.JoinPath(key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", c.cfg.MaxObjectBytes-1))
	signV4(req, c.cfg.Creds, c.cfg.Region, emptyPayloadSHA256, c.cfg.Now())

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("objectstore: reading %s: %w", key, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// 206 for a served range, 200 when the object is smaller than the range asked for.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, statusErr("reading "+key, resp)
	}
	// LimitReader as well as the Range header: the ceiling must hold even if the store ignores the range,
	// which some S3-compatible implementations do for small objects.
	return io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxObjectBytes))
}

// statusErr turns a non-2xx into an error carrying a bounded slice of the body, because S3's XML error
// documents name the actual cause (SignatureDoesNotMatch, NoSuchBucket, AccessDenied) and a bare status
// code sends the reader to the wrong problem.
func statusErr(what string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return fmt.Errorf("objectstore: %s: %s: %s", what, resp.Status, strings.TrimSpace(string(body)))
}

// storeHost returns the endpoint's host for the Event. HOST ONLY: the endpoint may carry credentials in a
// URL, and an Event is durable evidence that gets read by people who should not be handed a secret.
func (c *Client) storeHost() string {
	u, err := url.Parse(c.cfg.Endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}
