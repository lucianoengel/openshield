package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// THE READ HALF OF SCIM, which had no tests at all.
//
// D380 covered create, patch, replace and delete — the writes — and left GET and search at zero. They are
// not decoration: a provider calls SEARCH BEFORE IT CREATES, to find out whether the user already exists.
// A search that answers wrongly does not fail loudly; it makes the provider create a duplicate operator
// identity, or skip creating one that is missing.

func scimSearchFor(t *testing.T, s *controlplane.Server, token, filter string) (int, map[string]any) {
	t.Helper()
	rec := scimReq(t, s, http.MethodGet, scimUsersPath+"?filter="+url.QueryEscape(filter), token, "")
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("search returned unparseable JSON: %v\n%s", err, rec.Body.String())
	}
	return rec.Code, body
}

const scimUsersPath = "/scim/v2/Users"

func totalResults(t *testing.T, body map[string]any) int {
	t.Helper()
	n, ok := body["totalResults"].(float64)
	if !ok {
		t.Fatalf("no totalResults in %v", body)
	}
	return int(n)
}

func TestScimSearchFindsAnExistingUserSoTheProviderDoesNotDuplicateIt(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "search-hit@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	if rec := scimReq(t, s, http.MethodPost, scimUsersPath, "scim-secret",
		`{"userName":"`+who+`","active":true}`); rec.Code != http.StatusCreated {
		t.Fatalf("create returned %d: %s", rec.Code, rec.Body.String())
	}

	_, body := scimSearchFor(t, s, "scim-secret", `userName eq "`+who+`"`)
	if got := totalResults(t, body); got != 1 {
		t.Fatalf("totalResults = %d, want 1 — the provider would create a duplicate identity: %v", got, body)
	}
	res, ok := body["Resources"].([]any)
	if !ok || len(res) != 1 {
		t.Fatalf("Resources = %v, want one entry", body["Resources"])
	}
	if name := res[0].(map[string]any)["userName"]; name != who {
		t.Fatalf("search returned userName %v, want %s", name, who)
	}
}

func TestScimSearchForAnUnknownUserIsEmptyRatherThanAnError(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")

	code, body := scimSearchFor(t, s, "scim-secret", `userName eq "nobody-here@corp.example"`)
	if code != http.StatusOK {
		t.Fatalf("searching for an absent user returned %d — a provider reads that as a broken endpoint "+
			"and stops provisioning, rather than as 'this user does not exist yet'", code)
	}
	if got := totalResults(t, body); got != 0 {
		t.Fatalf("totalResults = %d, want 0", got)
	}
	// `null` is not an empty list. A provider iterating the response can fault on it, and the difference
	// only shows up against the one implementation nobody tested with.
	res, ok := body["Resources"].([]any)
	if !ok {
		t.Fatalf("Resources is %T (%v), want an empty JSON array", body["Resources"], body["Resources"])
	}
	if len(res) != 0 {
		t.Fatalf("Resources = %v, want empty", res)
	}
}

// userNameFromFilter parses exactly one filter shape and returns "" for everything else. The safe reading
// of "" is NO MATCH; the dangerous one is NO FILTER, therefore match everything. SCIM's filter grammar is
// large and this endpoint implements a sliver of it, so unrecognised filters are not rare — they are the
// normal case for any provider that sends something slightly different.
//
// STATED PLAINLY: no small mutation of the current code can fail this test, because search resolves one
// exact name and has no "return everything" path to reach. It is a REGRESSION GUARD, not evidence about
// today's logic — it exists so that the day someone adds real filter support, or makes an empty filter mean
// "list users", the roster does not quietly become readable in bulk. That is worth a test even though it
// cannot fail now, but it would be dishonest to count it among the mutation kills.
func TestAnUnrecognisedFilterMatchesNothingRatherThanEveryone(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "filter-victim@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}

	for _, filter := range []string{
		"",
		`displayName eq "x"`,
		`userName sw "filter"`,
		`userName eq`,
		`emails[type eq "work"].value eq "x"`,
		`userName ne "nobody"`,
		"userName",
	} {
		t.Run(filter, func(t *testing.T) {
			code, body := scimSearchFor(t, s, "scim-secret", filter)
			if code != http.StatusOK {
				t.Fatalf("filter %q returned %d", filter, code)
			}
			if got := totalResults(t, body); got != 0 {
				t.Fatalf("filter %q matched %d users — an unparsed filter is being read as 'match all', "+
					"which hands the provider the whole roster", filter, got)
			}
		})
	}
}

// The prefix match is case-insensitive but the value is sliced out of the ORIGINAL string, so the two have
// to stay in step. Non-ASCII input is included because ToLower can change a string's BYTE LENGTH, and the
// slice offset is computed from the lowercased form.
func TestFilterParsingHandlesCaseAndOddInput(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "case-test@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		filter string
		want   int
	}{
		{"canonical", `userName eq "` + who + `"`, 1},
		{"upper-case attribute", `USERNAME EQ "` + who + `"`, 1},
		{"mixed case", `UserName Eq "` + who + `"`, 1},
		{"leading whitespace", `   userName eq "` + who + `"`, 1},
		{"unquoted value", `userName eq ` + who, 1},
		{"unknown user", `userName eq "absent@corp.example"`, 0},
		{"empty value", `userName eq ""`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := scimSearchFor(t, s, "scim-secret", tc.filter)
			if code != http.StatusOK {
				t.Fatalf("filter %q returned %d", tc.filter, code)
			}
			if got := totalResults(t, body); got != tc.want {
				t.Fatalf("filter %q matched %d, want %d", tc.filter, got, tc.want)
			}
		})
	}

	// Must not panic or mis-slice. Turkish dotted capital I lowercases to two runes, so the lowercased
	// string is LONGER than the original — the exact condition that makes a byte offset taken from one and
	// applied to the other go wrong.
	for _, odd := range []string{"İserName eq \"x\"", "ＵserName eq \"x\"", "userName eq \"\xff\xfe\"", "\x00"} {
		code, _ := scimSearchFor(t, s, "scim-secret", odd)
		if code != http.StatusOK {
			t.Fatalf("filter %q returned %d rather than an empty result", odd, code)
		}
	}
}

func TestScimGetReportsWhetherTheOperatorIsStillActive(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	ctx := context.Background()
	const who = "get-test@corp.example"
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM operator_roles WHERE identity = $1`, who) })

	if rec := scimReq(t, s, http.MethodGet, scimUsersPath+"/"+who, "scim-secret", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET for an unknown user returned %d, want 404", rec.Code)
	}

	if err := s.SetOperatorRole(ctx, who, "admin", "test"); err != nil {
		t.Fatal(err)
	}
	active := scimGetActive(t, s, who)
	if !active {
		t.Fatal("a live operator reads as inactive — the provider would treat them as already deprovisioned")
	}

	// The provider deactivates them; a subsequent GET has to agree, or a reconciliation loop will keep
	// re-sending the deactivation it already made.
	if rec := scimReq(t, s, http.MethodPatch, scimUsersPath+"/"+who, "scim-secret",
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`); rec.Code != http.StatusOK {
		t.Fatalf("deactivation returned %d", rec.Code)
	}
	if scimGetActive(t, s, who) {
		t.Fatal("a deactivated operator still reads as active")
	}
}

func scimGetActive(t *testing.T, s *controlplane.Server, who string) bool {
	t.Helper()
	rec := scimReq(t, s, http.MethodGet, scimUsersPath+"/"+who, "scim-secret", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d: %s", who, rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET returned unparseable JSON: %v", err)
	}
	if body["userName"] != who {
		t.Fatalf("GET returned userName %v, want %s", body["userName"], who)
	}
	active, ok := body["active"].(bool)
	if !ok {
		t.Fatalf("no active flag in %v", body)
	}
	return active
}

// The read endpoints must sit behind the same token as the writes. A search that answered without one
// would hand the whole operator roster to anyone who could reach the port.
func TestScimReadsNeedTheScimToken(t *testing.T) {
	pool := requireDB(t)
	s := controlplane.New(pool)
	t.Setenv("OPENSHIELD_SCIM_TOKEN", "scim-secret")

	for _, tc := range []struct{ name, path, token string }{
		{"search, no token", scimUsersPath + `?filter=userName+eq+%22x%22`, ""},
		{"search, wrong token", scimUsersPath + `?filter=userName+eq+%22x%22`, "not-the-token"},
		{"get, no token", scimUsersPath + "/someone@corp.example", ""},
		{"get, wrong token", scimUsersPath + "/someone@corp.example", "not-the-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := scimReq(t, s, http.MethodGet, tc.path, tc.token, "")
			if rec.Code == http.StatusOK {
				t.Fatalf("%s was served anyway (%d)", tc.name, rec.Code)
			}
		})
	}
}
