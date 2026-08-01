package objectstore

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// WHO CAN READ IT (DSPM-2).
//
// The sweep answers "where is my sensitive data". On its own that ranks nothing: a bucket of customer
// records the whole internet can read and a bucket only one service role can read produce identical
// findings, and an operator handed both has to go and check each one by hand — which is the work the
// discovery was supposed to have done. Exposure is the field that turns a list into a queue.
//
// EVERY DETERMINATION HERE IS THREE-VALUED, and that is the design. "Public", "private" and NOT KNOWN are
// different answers, and the third one is the one a scanner is tempted to round down. A credential that can
// list objects but not read `?acl` produces no ACL — and reporting that as private is the exact shape of
// D31: a gap that is silent. So a probe that could not run is recorded by name in Unchecked, and the
// exposure stays Unknown rather than becoming a reassurance nobody re-checks.
//
// THE BLOCK-PUBLIC-ACCESS INTERACTION IS THE PART THAT IS EASY TO GET WRONG, so it is anchored to the AWS
// documentation rather than to intuition. Of the four settings, only TWO neuter access that already exists:
//
//   - IgnorePublicAcls — "causes Amazon S3 to ignore all public ACLs on a bucket and any objects that it
//     contains". An existing public ACL stops working. NEUTERS.
//   - RestrictPublicBuckets — "restricts access to a bucket with a public policy to only AWS service
//     principals and authorized users within the bucket owner's account". NEUTERS.
//   - BlockPublicAcls — rejects new public-ACL calls; "existing policies and ACLs for buckets and objects
//     aren't modified". Does NOT neuter.
//   - BlockPublicPolicy — rejects PutBucketPolicy; "doesn't affect existing ... bucket policies". Does NOT
//     neuter.
//
// Treating all four as protective is the common mistake and it under-reports live exposure. Treating none
// of them as protective is the other mistake and it reports buckets that are already safe, which trains an
// operator to ignore the finding. Both directions cost the same thing in the end.
//
// One more consequence, in our favour: on real AWS, GetBucketAcl "always returns the effective permissions",
// so a public grant already suppressed by IgnorePublicAcls does not even appear. On MinIO, Ceph and the rest
// it does. Applying the rule ourselves is therefore idempotent on AWS and load-bearing everywhere else.

// Exposure is who can read a bucket. The zero value is UNKNOWN on purpose: a struct nobody filled in must
// not read as "private".
type Exposure int

const (
	// ExposureUnknown — the probes needed to decide did not run or were refused. NOT a synonym for private.
	ExposureUnknown Exposure = iota
	// ExposurePrivate — no grant to anonymous or to every authenticated principal was found, and every
	// probe that could have found one succeeded.
	ExposurePrivate
	// ExposureAuthenticated — readable by ANY authenticated principal of the store, which on a public
	// cloud means any account in the world, not any account of yours.
	ExposureAuthenticated
	// ExposurePublic — readable anonymously.
	ExposurePublic
)

func (e Exposure) String() string {
	switch e {
	case ExposurePrivate:
		return "PRIVATE"
	case ExposureAuthenticated:
		return "AUTHENTICATED"
	case ExposurePublic:
		return "PUBLIC"
	default:
		return "UNKNOWN"
	}
}

// Encryption is whether the bucket encrypts new objects by default. Three-valued for the same reason
// Exposure is.
type Encryption int

const (
	EncryptionUnknown Encryption = iota
	EncryptionAbsent
	EncryptionPresent
)

func (e Encryption) String() string {
	switch e {
	case EncryptionAbsent:
		return "ABSENT"
	case EncryptionPresent:
		return "PRESENT"
	default:
		return "UNKNOWN"
	}
}

// Access is the bucket's access context: the answer to "who can read this" plus the honest record of what
// could not be established.
type Access struct {
	Exposure   Exposure
	Encryption Encryption
	// Blocked reports that a Block Public Access setting NEUTERED a grant that would otherwise have exposed
	// the bucket. It is not "a block setting is configured" — a setting that only rejects future calls
	// changes nothing about today, and reporting it as protection is how a live exposure gets filed as safe.
	Blocked bool
	// Reasons say WHY, in the operator's words, so a finding can be acted on without re-running the probes.
	Reasons []string
	// Unchecked names each probe that could not run. Non-empty means this picture is INCOMPLETE.
	Unchecked []string
}

// Known reports whether the exposure was actually established.
func (a Access) Known() bool { return a.Exposure != ExposureUnknown }

// String renders the access context for an operator.
func (a Access) String() string {
	s := "exposure " + a.Exposure.String()
	if a.Blocked {
		s += " (a public grant exists but is NEUTERED by block-public-access)"
	}
	if len(a.Unchecked) > 0 {
		s += "; NOT CHECKED: " + strings.Join(a.Unchecked, ", ")
	}
	return s
}

// The two predefined grantee groups. Any permission granted to these is what S3 itself calls a public ACL.
const (
	groupAllUsers           = "http://acs.amazonaws.com/groups/global/AllUsers"
	groupAuthenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

type aclPolicy struct {
	XMLName xml.Name `xml:"AccessControlPolicy"`
	Grants  []struct {
		Grantee struct {
			URI string `xml:"URI"`
		} `xml:"Grantee"`
		Permission string `xml:"Permission"`
	} `xml:"AccessControlList>Grant"`
}

type publicAccessBlock struct {
	XMLName               xml.Name `xml:"PublicAccessBlockConfiguration"`
	BlockPublicAcls       bool     `xml:"BlockPublicAcls"`
	IgnorePublicAcls      bool     `xml:"IgnorePublicAcls"`
	BlockPublicPolicy     bool     `xml:"BlockPublicPolicy"`
	RestrictPublicBuckets bool     `xml:"RestrictPublicBuckets"`
}

type sseConfig struct {
	XMLName xml.Name `xml:"ServerSideEncryptionConfiguration"`
	Rules   []struct {
		Default struct {
			Algorithm string `xml:"SSEAlgorithm"`
		} `xml:"ApplyServerSideEncryptionByDefault"`
	} `xml:"Rule"`
}

// Access probes the bucket's access context.
//
// FOUR SUB-RESOURCE READS, each independently allowed to fail. They are separate permissions
// (s3:GetBucketAcl, s3:GetBucketPolicy, s3:GetBucketPublicAccessBlock, s3:GetEncryptionConfiguration) and
// a discovery credential routinely holds some and not others, so one refusal must narrow the answer rather
// than end it.
//
// It returns no error: the failure of a probe IS the result, recorded in Unchecked. An error return would
// invite a caller to abandon the sweep over a permission it was never going to have, and a sweep that does
// not run finds nothing at all.
func (c *Client) Access(ctx context.Context) Access {
	var a Access

	block, blockOK := c.probeBlock(ctx, &a)
	aclExp := c.probeACL(ctx, &a)
	polExp := c.probePolicy(ctx, &a)
	a.Encryption = c.probeEncryption(ctx, &a)

	// NEUTERING, applied per SOURCE, because the two settings that neuter cover different sources: an
	// ignored ACL says nothing about a public policy, and a restricted public bucket says nothing about an
	// ACL. Collapsing them into one "blocked" flag applied to the total is the version of this that quietly
	// clears a bucket that is still open.
	if blockOK && block.IgnorePublicAcls && aclExp > ExposurePrivate {
		a.Reasons = append(a.Reasons, "a public ACL grant exists but IgnorePublicAcls is set, so the store ignores it")
		a.Blocked = true
		aclExp = ExposurePrivate
	}
	if blockOK && block.RestrictPublicBuckets && polExp > ExposurePrivate {
		a.Reasons = append(a.Reasons, "the bucket policy is public but RestrictPublicBuckets is set, so access is restricted to the owning account")
		a.Blocked = true
		polExp = ExposurePrivate
	}

	a.Exposure = resolveExposure(aclExp, polExp, len(a.Unchecked) > 0)
	sort.Strings(a.Unchecked)
	return a
}

// resolveExposure combines what the two sources said.
//
// A POSITIVE FINDING SURVIVES AN INCOMPLETE PICTURE: if the ACL proves the bucket is world-readable, it does
// not matter that the policy could not be read — it is public either way, and downgrading a proven exposure
// to "unknown" because something else was unreadable would lose the only finding that mattered.
//
// A NEGATIVE ONE DOES NOT: "nothing found" from a probe set with a hole in it is exactly the reassurance
// this package refuses to give, so an unchecked probe turns private into unknown.
func resolveExposure(acl, pol Exposure, incomplete bool) Exposure {
	worst := acl
	if pol > worst {
		worst = pol
	}
	if worst > ExposurePrivate {
		return worst
	}
	if incomplete {
		return ExposureUnknown
	}
	return worst
}

// probeACL reads the bucket ACL. Any permission to AllUsers or AuthenticatedUsers counts — S3's own
// definition of a public ACL — because READ_ACP and WRITE are exposures too, just different ones.
//
// AllUsers and AuthenticatedUsers are kept APART here, where AWS's block-public-access rules lump them
// together as "public". They are not the same thing to an operator: one is the open internet, the other is
// anybody who has an account with the provider. Both are findings; only one is the headline.
func (c *Client) probeACL(ctx context.Context, a *Access) Exposure {
	body, status, err := c.subResource(ctx, "acl")
	if err != nil {
		a.Unchecked = append(a.Unchecked, uncheckedReason("bucket ACL", status, err))
		return ExposureUnknown
	}
	var p aclPolicy
	if err := xml.Unmarshal(body, &p); err != nil {
		a.Unchecked = append(a.Unchecked, "bucket ACL (the store's response did not parse)")
		return ExposureUnknown
	}
	exp := ExposurePrivate
	for _, g := range p.Grants {
		switch g.Grantee.URI {
		case groupAllUsers:
			a.Reasons = append(a.Reasons, "the bucket ACL grants "+g.Permission+" to AllUsers (anonymous)")
			exp = ExposurePublic
		case groupAuthenticatedUsers:
			a.Reasons = append(a.Reasons, "the bucket ACL grants "+g.Permission+" to AuthenticatedUsers (any account on this store)")
			if exp < ExposureAuthenticated {
				exp = ExposureAuthenticated
			}
		}
	}
	return exp
}

// bucketPolicy is the subset of an IAM policy document this needs. Principal and Action are `any` because
// both are legally either a string or a list, and a decoder that assumed one shape would silently skip the
// other — which on this field means silently skipping a public statement.
type bucketPolicy struct {
	Statement []struct {
		Effect    string          `json:"Effect"`
		Principal any             `json:"Principal"`
		Action    any             `json:"Action"`
		Condition map[string]any  `json:"Condition"`
		Resource  json.RawMessage `json:"Resource"`
	} `json:"Statement"`
}

// probePolicy reads the bucket policy and decides whether it grants access to everyone.
//
// THE RULE IS S3'S OWN, and it is the opposite way round from the obvious one: a policy is assumed PUBLIC
// and must qualify as non-public, by granting access only to FIXED values of a specific set of condition
// keys. So a wildcard inside a condition does not save it — AWS's own worked example marks
// `{"StringLike": {"aws:SourceVpc": "vpc-*"}}` as public, while the same key pinned to `vpc-91237329` is
// not. Assuming "has a Condition, therefore restricted" is the intuitive reading and it is wrong in the
// unsafe direction; this was corrected against the documentation rather than reasoned about.
//
// WHAT THIS IS: a conservative approximation, deliberately erring toward reporting exposure. It does not
// evaluate the condition's operator semantics, and it does not resolve IAM policy variables. A finding it
// produces is worth a look; an absence it produces is only as strong as the credential that read it, which
// is why Unchecked exists.
func (c *Client) probePolicy(ctx context.Context, a *Access) Exposure {
	body, status, err := c.subResource(ctx, "policy")
	if err != nil {
		// No policy at all is the common case and is a real determination, not a failure: nothing is
		// granted by a policy that does not exist.
		if status == http.StatusNotFound {
			return ExposurePrivate
		}
		a.Unchecked = append(a.Unchecked, uncheckedReason("bucket policy", status, err))
		return ExposureUnknown
	}
	var p bucketPolicy
	if err := json.Unmarshal(body, &p); err != nil {
		a.Unchecked = append(a.Unchecked, "bucket policy (the store's response did not parse)")
		return ExposureUnknown
	}
	exp := ExposurePrivate
	for _, st := range p.Statement {
		if !strings.EqualFold(st.Effect, "Allow") || !principalIsEveryone(st.Principal) {
			continue
		}
		if conditionPinsToFixedValue(st.Condition) {
			a.Reasons = append(a.Reasons, "the bucket policy has a wildcard-principal statement, restricted to a fixed condition value")
			continue
		}
		a.Reasons = append(a.Reasons, "the bucket policy allows "+actionSummary(st.Action)+` to Principal "*" with no restricting condition`)
		exp = ExposurePublic
	}
	return exp
}

// principalIsEveryone recognises the wildcard principal in each of the shapes S3 accepts: the bare "*",
// {"AWS": "*"} and {"AWS": ["*", ...]}. Recognising only the first is a real omission — {"AWS":"*"} is the
// form the console writes.
func principalIsEveryone(p any) bool {
	switch v := p.(type) {
	case string:
		return v == "*"
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == "*" {
				return true
			}
		}
	case map[string]any:
		for _, inner := range v {
			if principalIsEveryone(inner) {
				return true
			}
		}
	}
	return false
}

// fixedValueConditionKeys is the set S3 documents as able to make a wildcard-principal statement non-public.
// It is a CLOSED list on purpose: a condition on some other key (say a tag) does not make the statement
// non-public by S3's rule, and accepting any condition at all would silently clear every public bucket that
// happened to carry one.
var fixedValueConditionKeys = map[string]bool{
	"aws:principalorgid":        true,
	"aws:sourceip":              true,
	"aws:sourcearn":             true,
	"aws:sourcevpc":             true,
	"aws:sourcevpce":            true,
	"aws:sourceowner":           true,
	"aws:sourceaccount":         true,
	"aws:userid":                true,
	"s3:dataaccesspointarn":     true,
	"s3:dataaccesspointaccount": true,
}

// conditionPinsToFixedValue reports whether the condition restricts the statement to fixed values of a
// recognised key. A wildcard anywhere in the value fails the test, per S3's rule and its worked example.
func conditionPinsToFixedValue(cond map[string]any) bool {
	for _, kv := range cond {
		m, ok := kv.(map[string]any)
		if !ok {
			continue
		}
		for key, val := range m {
			if !fixedValueConditionKeys[strings.ToLower(key)] {
				continue
			}
			if valuesAreFixed(val) {
				return true
			}
		}
	}
	return false
}

func valuesAreFixed(v any) bool {
	switch t := v.(type) {
	case string:
		return t != "" && !strings.ContainsAny(t, "*?") && !strings.Contains(t, "${")
	case []any:
		if len(t) == 0 {
			return false
		}
		for _, e := range t {
			if !valuesAreFixed(e) {
				return false
			}
		}
		return true
	}
	return false
}

// actionSummary renders the action(s) of a statement for the reason line, bounded so a policy with a
// hundred actions does not produce a hundred-line finding.
func actionSummary(a any) string {
	switch t := a.(type) {
	case string:
		return t
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
			if len(out) == 3 {
				return strings.Join(out, ",") + ",…"
			}
		}
		if len(out) == 0 {
			return "an unreadable action"
		}
		return strings.Join(out, ",")
	}
	return "an unreadable action"
}

// probeBlock reads the Block Public Access configuration.
//
// ABSENT IS A REAL ANSWER HERE, and it is the safe direction: a 404 on AWS means no configuration exists, a
// 501/NotImplemented from a store that never had the feature means the same thing operationally — nothing
// is neutering anything — so both resolve to "no block" and the exposure stands as found. A permission
// refusal is different and is recorded, because then a bucket that IS protected may be reported exposed.
func (c *Client) probeBlock(ctx context.Context, a *Access) (publicAccessBlock, bool) {
	var b publicAccessBlock
	body, status, err := c.subResource(ctx, "publicAccessBlock")
	if err != nil {
		if status == http.StatusNotFound || status == http.StatusNotImplemented {
			return b, true // genuinely nothing configured
		}
		a.Unchecked = append(a.Unchecked, uncheckedReason("block-public-access settings", status, err))
		return b, false
	}
	if err := xml.Unmarshal(body, &b); err != nil {
		a.Unchecked = append(a.Unchecked, "block-public-access settings (the store's response did not parse)")
		return b, false
	}
	return b, true
}

func (c *Client) probeEncryption(ctx context.Context, a *Access) Encryption {
	body, status, err := c.subResource(ctx, "encryption")
	if err != nil {
		if status == http.StatusNotFound || status == http.StatusNotImplemented {
			return EncryptionAbsent
		}
		a.Unchecked = append(a.Unchecked, uncheckedReason("default encryption", status, err))
		return EncryptionUnknown
	}
	var s sseConfig
	if err := xml.Unmarshal(body, &s); err != nil {
		a.Unchecked = append(a.Unchecked, "default encryption (the store's response did not parse)")
		return EncryptionUnknown
	}
	for _, r := range s.Rules {
		if r.Default.Algorithm != "" {
			return EncryptionPresent
		}
	}
	return EncryptionAbsent
}

// uncheckedReason names the probe and why it did not answer, because "unchecked" without a cause sends an
// operator to look at the bucket when the fix is a missing IAM permission on the scanner.
func uncheckedReason(what string, status int, err error) string {
	switch status {
	case http.StatusForbidden, http.StatusUnauthorized:
		return what + " (this credential is not permitted to read it)"
	case 0:
		return fmt.Sprintf("%s (the store could not be reached: %v)", what, err)
	default:
		return fmt.Sprintf("%s (the store answered %d)", what, status)
	}
}

// subResource performs a signed GET on a bucket sub-resource such as ?acl.
//
// The status is returned ALONGSIDE the error because the callers distinguish 404 (there is nothing
// configured — a real answer) from 403 (we are not allowed to look — not an answer), and an error string
// they would have to match on is not a contract.
func (c *Client) subResource(ctx context.Context, name string) ([]byte, int, error) {
	u, err := url.Parse(strings.TrimRight(c.cfg.Endpoint, "/") + "/" + c.cfg.Bucket)
	if err != nil {
		return nil, 0, fmt.Errorf("objectstore: building the %s URL: %w", name, err)
	}
	// A sub-resource is a valueless query parameter, and it must survive signing exactly as sent.
	u.RawQuery = name + "="
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	signV4(req, c.cfg.Creds, c.cfg.Region, emptyPayloadSHA256, c.cfg.Now())

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("objectstore: reading ?%s on %s: %w", name, c.cfg.Bucket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, statusErr("reading ?"+name+" on "+c.cfg.Bucket, resp)
	}
	// Bounded: a bucket policy is kilobytes, and a store that streams forever must not exhaust this process.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("objectstore: reading the ?%s response: %w", name, err)
	}
	return body, resp.StatusCode, nil
}
