package objectstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "github.com/lucianoengel/openshield/internal/core/corev1"
)

// bucketFixture is a fake S3-compatible store that answers only the sub-resources it is given, and answers
// everything else with the status a real store uses for "there is nothing configured".
//
// The 404 default matters: it means every test states which probes it is exercising, and a probe a test
// forgot cannot silently return the previous test's body.
type bucketFixture struct {
	acl        string
	policy     string
	block      string
	encryption string
	// status overrides the response code per sub-resource, so a test can express "this credential is not
	// permitted to read the ACL" rather than "the ACL is empty" — the distinction the whole file is about.
	status map[string]int
}

func (f bucketFixture) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for _, name := range []string{"acl", "policy", "publicAccessBlock", "encryption"} {
			if !q.Has(name) {
				continue
			}
			if code, ok := f.status[name]; ok {
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
				return
			}
			body := map[string]string{
				"acl": f.acl, "policy": f.policy, "publicAccessBlock": f.block, "encryption": f.encryption,
			}[name]
			if body == "" {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchConfiguration</Code></Error>`))
				return
			}
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f bucketFixture) access(t *testing.T) Access {
	t.Helper()
	srv := f.serve(t)
	c, err := New(Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "b",
		Creds: Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c.Access(context.Background())
}

func aclGranting(uri, perm string) string {
	return `<AccessControlPolicy><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>` +
		uri + `</URI></Grantee><Permission>` + perm + `</Permission></Grant></AccessControlList></AccessControlPolicy>`
}

const aclOwnerOnly = `<AccessControlPolicy><AccessControlList><Grant><Grantee xsi:type="CanonicalUser"><ID>owner</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`

func blockConfig(acls, ignore, policy, restrict bool) string {
	b := func(v bool) string {
		if v {
			return "true"
		}
		return "false"
	}
	return `<PublicAccessBlockConfiguration><BlockPublicAcls>` + b(acls) +
		`</BlockPublicAcls><IgnorePublicAcls>` + b(ignore) +
		`</IgnorePublicAcls><BlockPublicPolicy>` + b(policy) +
		`</BlockPublicPolicy><RestrictPublicBuckets>` + b(restrict) + `</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
}

func TestPublicACLIsReportedPublic(t *testing.T) {
	a := bucketFixture{acl: aclGranting(groupAllUsers, "READ")}.access(t)
	if a.Exposure != ExposurePublic {
		t.Fatalf("exposure = %v, want PUBLIC (reasons %v, unchecked %v)", a.Exposure, a.Reasons, a.Unchecked)
	}
	if len(a.Reasons) == 0 {
		t.Fatal("a public finding with no stated reason cannot be acted on without re-probing")
	}
}

func TestAuthenticatedUsersIsNotConflatedWithPublic(t *testing.T) {
	// S3's own block-public-access rules call both of these "public". They are kept apart here because they
	// are different findings: one is the open internet, the other is anybody with an account on the store.
	// Collapsing them would make every AuthenticatedUsers grant read as an internet-exposed bucket, and an
	// operator who chases three of those stops chasing the fourth.
	a := bucketFixture{acl: aclGranting(groupAuthenticatedUsers, "READ")}.access(t)
	if a.Exposure != ExposureAuthenticated {
		t.Fatalf("exposure = %v, want AUTHENTICATED", a.Exposure)
	}
}

func TestAnyPermissionToAllUsersCountsNotJustRead(t *testing.T) {
	// WRITE to AllUsers is a worse finding than READ, not a lesser one — anonymous upload is how a bucket
	// becomes a malware host. A detector that only looked for READ would miss it entirely.
	for _, perm := range []string{"READ", "WRITE", "READ_ACP", "FULL_CONTROL"} {
		a := bucketFixture{acl: aclGranting(groupAllUsers, perm)}.access(t)
		if a.Exposure != ExposurePublic {
			t.Errorf("%s to AllUsers: exposure = %v, want PUBLIC", perm, a.Exposure)
		}
	}
}

func TestFullyProbedPrivateBucketIsPrivateWithNothingUnchecked(t *testing.T) {
	a := bucketFixture{acl: aclOwnerOnly}.access(t)
	if a.Exposure != ExposurePrivate {
		t.Fatalf("exposure = %v, want PRIVATE (unchecked %v)", a.Exposure, a.Unchecked)
	}
	if len(a.Unchecked) != 0 {
		t.Fatalf("unchecked = %v, want none: a 404 on policy/block/encryption is a real answer, not a gap", a.Unchecked)
	}
	if a.Encryption != EncryptionAbsent {
		t.Fatalf("encryption = %v, want ABSENT", a.Encryption)
	}
}

// THE CENTRAL HONESTY TEST. A credential that can list objects but cannot read the bucket's ACL is the
// common case, and the tempting result is "no public grant found, therefore private". That is the reassuring
// answer nobody re-checks, produced from having looked at nothing.
func TestARefusedProbeYieldsUnknownNotPrivate(t *testing.T) {
	a := bucketFixture{
		acl:    aclOwnerOnly,
		status: map[string]int{"acl": http.StatusForbidden},
	}.access(t)
	if a.Exposure != ExposureUnknown {
		t.Fatalf("exposure = %v, want UNKNOWN — a probe that was refused is not a bucket that is private", a.Exposure)
	}
	if a.Known() {
		t.Fatal("Known() must be false when the exposure was never established")
	}
	joined := strings.Join(a.Unchecked, "|")
	if !strings.Contains(joined, "bucket ACL") || !strings.Contains(joined, "not permitted") {
		t.Fatalf("unchecked = %v, want it to name the ACL probe AND say the credential was refused — "+
			"'unchecked' without a cause sends an operator to the bucket when the fix is an IAM permission", a.Unchecked)
	}
}

func TestAProvenExposureSurvivesAnIncompletePicture(t *testing.T) {
	// The policy proves the bucket is open. That the ACL could not be read does not make it less open, and
	// downgrading to UNKNOWN here would discard the only finding that mattered.
	a := bucketFixture{
		policy: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`,
		status: map[string]int{"acl": http.StatusForbidden},
	}.access(t)
	if a.Exposure != ExposurePublic {
		t.Fatalf("exposure = %v, want PUBLIC despite the unreadable ACL", a.Exposure)
	}
	if len(a.Unchecked) == 0 {
		t.Fatal("the incomplete picture must still be recorded")
	}
}

// THE BLOCK-PUBLIC-ACCESS TABLE. Two of the four settings neuter access that already exists and two only
// reject future calls. Getting this wrong in either direction is a real failure: treating all four as
// protective files a live exposure as safe, and treating none as protective reports buckets that are
// already closed until the operator stops reading the findings.
func TestOnlyTheTwoSettingsThatAffectExistingAccessNeuterIt(t *testing.T) {
	publicACL := aclGranting(groupAllUsers, "READ")
	publicPolicy := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"*"}]}`

	cases := []struct {
		name        string
		acl, policy string
		block       string
		want        Exposure
		wantBlocked bool
	}{
		{"public ACL, IgnorePublicAcls ignores it", publicACL, "", blockConfig(false, true, false, false), ExposurePrivate, true},
		{"public ACL, BlockPublicAcls only rejects NEW ones", publicACL, "", blockConfig(true, false, false, false), ExposurePublic, false},
		{"public policy, RestrictPublicBuckets restricts it", "", publicPolicy, blockConfig(false, false, false, true), ExposurePrivate, true},
		{"public policy, BlockPublicPolicy only rejects NEW ones", "", publicPolicy, blockConfig(false, false, true, false), ExposurePublic, false},
		{"public ACL, RestrictPublicBuckets does not cover ACLs", publicACL, "", blockConfig(false, false, false, true), ExposurePublic, false},
		{"public policy, IgnorePublicAcls does not cover policies", "", publicPolicy, blockConfig(false, true, false, false), ExposurePublic, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acl := c.acl
			if acl == "" {
				acl = aclOwnerOnly
			}
			a := bucketFixture{acl: acl, policy: c.policy, block: c.block}.access(t)
			if a.Exposure != c.want {
				t.Errorf("exposure = %v, want %v (reasons %v)", a.Exposure, c.want, a.Reasons)
			}
			if a.Blocked != c.wantBlocked {
				t.Errorf("blocked = %v, want %v", a.Blocked, c.wantBlocked)
			}
		})
	}
}

func TestANeuteredGrantIsStillReportedAsPresent(t *testing.T) {
	// The exposure is private, but one setting away from not being. An operator deleting a
	// block-public-access configuration needs to know that a live public grant is waiting underneath it.
	a := bucketFixture{acl: aclGranting(groupAllUsers, "READ"), block: blockConfig(false, true, false, false)}.access(t)
	if !a.Blocked {
		t.Fatal("Blocked must record that a real public grant exists and is being suppressed")
	}
	if !strings.Contains(a.String(), "NEUTERED") {
		t.Fatalf("the rendered access context hides the suppressed grant: %q", a.String())
	}
}

func TestWildcardPrincipalIsRecognisedInEveryShapeS3Accepts(t *testing.T) {
	// {"AWS":"*"} is the form the console writes. A decoder that only handled the bare "*" would miss the
	// most common public bucket in existence.
	for _, principal := range []string{`"*"`, `{"AWS":"*"}`, `{"AWS":["arn:aws:iam::1:root","*"]}`} {
		pol := `{"Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"s3:GetObject","Resource":"*"}]}`
		a := bucketFixture{acl: aclOwnerOnly, policy: pol}.access(t)
		if a.Exposure != ExposurePublic {
			t.Errorf("Principal %s: exposure = %v, want PUBLIC", principal, a.Exposure)
		}
	}
}

func TestDenyAndNamedPrincipalsAreNotPublic(t *testing.T) {
	cases := map[string]string{
		"explicit deny to everyone": `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`,
		"a named account":           `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"*"}]}`,
	}
	for name, pol := range cases {
		a := bucketFixture{acl: aclOwnerOnly, policy: pol}.access(t)
		if a.Exposure != ExposurePrivate {
			t.Errorf("%s: exposure = %v, want PRIVATE", name, a.Exposure)
		}
	}
}

// S3's rule is the opposite way round from the intuitive one: a wildcard-principal statement is PUBLIC
// unless it is pinned to a FIXED value of a recognised condition key. AWS's own worked example marks
// {"StringLike":{"aws:SourceVpc":"vpc-*"}} public and the same key pinned to "vpc-91237329" non-public.
// "It has a Condition, so it is restricted" is the wrong reading, and it is wrong in the unsafe direction.
func TestAConditionOnlySavesAPolicyWhenItPinsAFixedValue(t *testing.T) {
	cases := []struct {
		name string
		cond string
		want Exposure
	}{
		{"fixed VPC", `{"StringEquals":{"aws:SourceVpc":"vpc-91237329"}}`, ExposurePrivate},
		{"wildcarded VPC", `{"StringLike":{"aws:SourceVpc":"vpc-*"}}`, ExposurePublic},
		{"fixed org id", `{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, ExposurePrivate},
		{"a key that is not on S3's list", `{"StringEquals":{"aws:RequestTag/team":"finance"}}`, ExposurePublic},
		{"an IAM policy variable is not a fixed value", `{"StringEquals":{"aws:userid":"${aws:username}"}}`, ExposurePublic},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":` + c.cond + `}]}`
			a := bucketFixture{acl: aclOwnerOnly, policy: pol}.access(t)
			if a.Exposure != c.want {
				t.Fatalf("exposure = %v, want %v (reasons %v)", a.Exposure, c.want, a.Reasons)
			}
		})
	}
}

func TestEncryptionIsThreeValued(t *testing.T) {
	sse := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
	if got := (bucketFixture{acl: aclOwnerOnly, encryption: sse}).access(t).Encryption; got != EncryptionPresent {
		t.Errorf("configured SSE: encryption = %v, want PRESENT", got)
	}
	if got := (bucketFixture{acl: aclOwnerOnly}).access(t).Encryption; got != EncryptionAbsent {
		t.Errorf("no SSE configuration: encryption = %v, want ABSENT", got)
	}
	refused := bucketFixture{acl: aclOwnerOnly, status: map[string]int{"encryption": http.StatusForbidden}}.access(t)
	if refused.Encryption != EncryptionUnknown {
		t.Errorf("refused probe: encryption = %v, want UNKNOWN — not permitted to look is not unencrypted", refused.Encryption)
	}
}

func TestAStoreThatDoesNotImplementBlockPublicAccessDoesNotHideAnExposure(t *testing.T) {
	// MinIO, Ceph and most S3-compatible stores never had the feature and answer 501. Operationally that
	// means nothing is neutering anything, so the exposure must stand as found — the safe direction. If it
	// were recorded as an unchecked probe instead, every public bucket on every non-AWS store would be
	// downgraded to UNKNOWN and the finding would be lost on exactly the deployments this product targets.
	a := bucketFixture{
		acl:    aclGranting(groupAllUsers, "READ"),
		status: map[string]int{"publicAccessBlock": http.StatusNotImplemented},
	}.access(t)
	if a.Exposure != ExposurePublic {
		t.Fatalf("exposure = %v, want PUBLIC (unchecked %v)", a.Exposure, a.Unchecked)
	}
	if len(a.Unchecked) != 0 {
		t.Fatalf("unchecked = %v, want none: a store without the feature is a real answer", a.Unchecked)
	}
}

// The sweep must probe the bucket ONCE and put the answer on EVERY event — an object whose access context
// is missing is indistinguishable downstream from one in a bucket nobody could read the configuration of.
func TestEveryDiscoveredObjectCarriesTheBucketAccessContext(t *testing.T) {
	var aclCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Has("acl"):
			aclCalls++
			_, _ = w.Write([]byte(aclGranting(groupAllUsers, "READ")))
		case q.Has("policy"), q.Has("publicAccessBlock"), q.Has("encryption"):
			w.WriteHeader(http.StatusNotFound)
		case q.Get("list-type") == "2":
			_, _ = w.Write([]byte(`<ListBucketResult><Contents><Key>a.csv</Key><Size>4</Size></Contents>` +
				`<Contents><Key>b.csv</Key><Size>4</Size></Contents></ListBucketResult>`))
		default:
			_, _ = w.Write([]byte("data"))
		}
	}))
	defer srv.Close()

	c, err := New(Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "b",
		Creds: Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := NewSweeper(c, nil)
	var seen int
	for {
		ev, err := s.Next(context.Background())
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if ev == nil {
			break
		}
		seen++
		ac := ev.GetObject().GetAccess()
		if ac.GetExposure() != corev1.ObjectExposure_OBJECT_EXPOSURE_PUBLIC {
			t.Fatalf("object %d: exposure = %v, want PUBLIC", seen, ac.GetExposure())
		}
	}
	if seen != 2 {
		t.Fatalf("swept %d objects, want 2", seen)
	}
	if aclCalls != 1 {
		t.Fatalf("the ACL was probed %d times, want 1: it is a property of the bucket, and 4 requests per "+
			"object is a sweep an operator turns off", aclCalls)
	}
	if !strings.Contains(s.Report().String(), "PUBLIC") {
		t.Fatalf("the sweep report does not state the exposure: %q", s.Report().String())
	}
}

// The Go and proto enums are mapped by an explicit switch, not a cast. This pins the pairing so that
// inserting a value into either declaration cannot silently relabel every stored finding.
func TestExposureEnumsAreMappedNotCast(t *testing.T) {
	for _, c := range []struct {
		in   Exposure
		want corev1.ObjectExposure
	}{
		{ExposureUnknown, corev1.ObjectExposure_OBJECT_EXPOSURE_UNSPECIFIED},
		{ExposurePrivate, corev1.ObjectExposure_OBJECT_EXPOSURE_PRIVATE},
		{ExposureAuthenticated, corev1.ObjectExposure_OBJECT_EXPOSURE_AUTHENTICATED},
		{ExposurePublic, corev1.ObjectExposure_OBJECT_EXPOSURE_PUBLIC},
	} {
		if got := exposureProto(c.in); got != c.want {
			t.Errorf("exposureProto(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, c := range []struct {
		in   Encryption
		want corev1.ObjectEncryption
	}{
		{EncryptionUnknown, corev1.ObjectEncryption_OBJECT_ENCRYPTION_UNSPECIFIED},
		{EncryptionAbsent, corev1.ObjectEncryption_OBJECT_ENCRYPTION_ABSENT},
		{EncryptionPresent, corev1.ObjectEncryption_OBJECT_ENCRYPTION_PRESENT},
	} {
		if got := encryptionProto(c.in); got != c.want {
			t.Errorf("encryptionProto(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
