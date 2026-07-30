package controlplane

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// SCIM 2.0 USER DEPROVISIONING (ZT-7, RFC 7643/7644), and deprovisioning is nearly all of the point.
//
// D372 made an operator's authority changeable and D373 gave them SSO. What was still manual is the thing
// enterprise IAM actually buys: when somebody leaves, or moves team, the identity provider deactivates them
// THERE and every downstream system follows. Without it, OpenShield relied on an administrator remembering
// to run `operator-role revoke`, and "we remember" is not a control.
//
// # PROVISIONING DELIBERATELY GRANTS NOTHING
//
// Creating a user here records the identity and NO role. That looks like an omission and is the same
// decision as D373's: the identity provider says who exists, this product says what they may do. A SCIM
// create that granted a tier — from a group claim, or a default — would put authorization back inside the
// credential path, which is the defect ZT-7 spent two changes removing.
//
// So the honest summary is: SCIM here closes the LEAVER half of joiner/mover/leaver, and the joiner half
// still ends with an administrator running `operator-role set`. That is a smaller claim than "SCIM support"
// usually implies and it is the one the design supports.
//
// # THE ENDPOINT IS NOT REACHABLE BY AN OPERATOR CREDENTIAL
//
// It authenticates with its own token, not an operator's certificate or bearer token. If an operator
// credential could reach it, an analyst could deactivate an admin — a privilege escalation through a
// provisioning API, which is a well-trodden way to lose a console.

// scimUsers is the SCIM 2.0 user resource path.
const scimUsers = "/scim/v2/Users"

var (
	scimDeprovisioned atomic.Int64
	scimProvisioned   atomic.Int64
)

// ScimDeprovisioned reports how many operators the identity provider has deactivated through SCIM.
func ScimDeprovisioned() int64 { return scimDeprovisioned.Load() }

// ScimProvisioned reports how many operator identities SCIM has recorded.
func ScimProvisioned() int64 { return scimProvisioned.Load() }

// scimToken is the credential the identity provider presents. Empty disables the endpoint entirely: a
// provisioning API that exists without being configured is an unauthenticated way into the roster.
func scimToken() string { return strings.TrimSpace(os.Getenv("OPENSHIELD_SCIM_TOKEN")) }

// scimUser is the subset of the SCIM user schema this understands.
//
// Deliberately small. SCIM is a large specification and implementing more of it than is used produces
// surface nobody tests — `userName` identifies the operator and `active` is the flag that matters.
type scimUser struct {
	Schemas  []string `json:"schemas,omitempty"`
	ID       string   `json:"id,omitempty"`
	UserName string   `json:"userName,omitempty"`
	Active   *bool    `json:"active,omitempty"`
}

// scimPatch is the PATCH body an identity provider sends to deactivate a user.
type scimPatch struct {
	Schemas    []string `json:"schemas,omitempty"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// ScimHandler serves the SCIM user endpoint.
//
// Its own token, compared in constant time. A provisioning API is a high-value target — it can remove an
// administrator's access — so it does not share a credential with anything else and is off unless a token
// is set.
func (s *Server) ScimHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := scimToken()
		if want == "" {
			http.Error(w, "SCIM provisioning is not enabled", http.StatusNotFound)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			// 401 rather than 403: the caller is unauthenticated, and saying which token was wrong would
			// help an attacker enumerate.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		id := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, scimUsers), "/")
		switch {
		case r.Method == http.MethodPost && id == "":
			s.scimCreate(w, r)
		case r.Method == http.MethodGet && id == "":
			s.scimSearch(w, r)
		case r.Method == http.MethodGet:
			s.scimGet(w, r, id)
		case r.Method == http.MethodPatch && id != "":
			s.scimPatch(w, r, id)
		case r.Method == http.MethodPut && id != "":
			s.scimReplace(w, r, id)
		case r.Method == http.MethodDelete && id != "":
			s.scimDelete(w, r, id)
		default:
			http.Error(w, "unsupported SCIM operation", http.StatusMethodNotAllowed)
		}
	})
}

func (s *Server) scimCreate(w http.ResponseWriter, r *http.Request) {
	var u scimUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&u); err != nil || u.UserName == "" {
		http.Error(w, "a SCIM user needs a userName", http.StatusBadRequest)
		return
	}
	// RECORDED WITH NO ROLE. The provider says this person exists; an administrator still decides what they
	// may do. See the file comment — granting here would put authorization back in the credential path.
	if err := s.recordOperatorIdentity(r.Context(), u.UserName, "scim"); err != nil {
		http.Error(w, "could not record the identity", http.StatusInternalServerError)
		return
	}
	scimProvisioned.Add(1)
	fmt.Fprintf(os.Stderr, "openshield-server: SCIM recorded operator %q with NO role — grant one with "+
		"`openshield-server operator-role set %s <tier>`. Provisioning identifies; it does not authorize.\n",
		u.UserName, u.UserName)
	writeScimUser(w, http.StatusCreated, u.UserName, true)
}

func (s *Server) scimPatch(w http.ResponseWriter, r *http.Request, id string) {
	var p scimPatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
		http.Error(w, "malformed SCIM patch", http.StatusBadRequest)
		return
	}
	for _, op := range p.Operations {
		// Providers differ on casing and on whether `path` is present, so both shapes are accepted:
		// {"path":"active","value":false} and {"value":{"active":false}}.
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		active, ok := activeFromPatch(op.Path, op.Value)
		if !ok {
			continue
		}
		s.applyScimActive(r.Context(), w, id, active)
		return
	}
	// A patch that changes nothing this understands is NOT an error — a provider syncing a display name
	// must not get a 400 and start retrying forever.
	writeScimUser(w, http.StatusOK, id, true)
}

func (s *Server) scimReplace(w http.ResponseWriter, r *http.Request, id string) {
	var u scimUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&u); err != nil {
		http.Error(w, "malformed SCIM user", http.StatusBadRequest)
		return
	}
	if u.Active != nil {
		s.applyScimActive(r.Context(), w, id, *u.Active)
		return
	}
	writeScimUser(w, http.StatusOK, id, true)
}

// scimDelete is deprovisioning by the other verb some providers use. Same effect: revoked, not forgotten.
func (s *Server) scimDelete(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.RevokeOperator(r.Context(), id, "scim"); err != nil {
		http.Error(w, "could not revoke", http.StatusInternalServerError)
		return
	}
	scimDeprovisioned.Add(1)
	fmt.Fprintf(os.Stderr, "openshield-server: SCIM DEPROVISIONED operator %q — access revoked immediately\n", id)
	w.WriteHeader(http.StatusNoContent)
}

// applyScimActive is the operation that matters: active=false revokes, immediately.
func (s *Server) applyScimActive(ctx context.Context, w http.ResponseWriter, id string, active bool) {
	if !active {
		// REVOKED, NOT DELETED. A revocation is a row (D372) — deleting would fall back to whatever the
		// operator's certificate says, which would restore the access this call exists to remove.
		if err := s.RevokeOperator(ctx, id, "scim"); err != nil {
			http.Error(w, "could not revoke", http.StatusInternalServerError)
			return
		}
		scimDeprovisioned.Add(1)
		fmt.Fprintf(os.Stderr, "openshield-server: SCIM DEPROVISIONED operator %q — access revoked "+
			"immediately\n", id)
		writeScimUser(w, http.StatusOK, id, false)
		return
	}
	// REACTIVATION DOES NOT RESTORE A ROLE. It clears the revocation only if an administrator has since
	// granted one; on its own it leaves the operator with no access, for the same reason a create does.
	if err := s.recordOperatorIdentity(ctx, id, "scim"); err != nil {
		http.Error(w, "could not record the identity", http.StatusInternalServerError)
		return
	}
	writeScimUser(w, http.StatusOK, id, true)
}

// activeFromPatch extracts the `active` value from either patch shape.
func activeFromPatch(path string, value json.RawMessage) (bool, bool) {
	if strings.EqualFold(strings.TrimSpace(path), "active") {
		var b bool
		if json.Unmarshal(value, &b) == nil {
			return b, true
		}
		return false, false
	}
	var obj struct {
		Active *bool `json:"active"`
	}
	if json.Unmarshal(value, &obj) == nil && obj.Active != nil {
		return *obj.Active, true
	}
	return false, false
}

func (s *Server) scimGet(w http.ResponseWriter, r *http.Request, id string) {
	role, revoked, err := s.lookupOperatorRole(r.Context(), id)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	_ = role
	writeScimUser(w, http.StatusOK, id, !revoked)
}

// scimSearch answers the lookup a provider does before creating, so it does not create duplicates.
func (s *Server) scimSearch(w http.ResponseWriter, r *http.Request) {
	name := userNameFromFilter(r.URL.Query().Get("filter"))
	resources := []map[string]any{}
	if name != "" {
		if _, revoked, err := s.lookupOperatorRole(r.Context(), name); err == nil {
			resources = append(resources, scimUserBody(name, !revoked))
		}
	}
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"Resources":    resources,
	})
}

// userNameFromFilter parses the one filter shape providers actually send: `userName eq "value"`.
//
// Not a general filter parser, deliberately. SCIM's filter grammar is large, and implementing it would be
// building an expression evaluator that runs on input from outside — surface this endpoint does not need.
func userNameFromFilter(filter string) string {
	f := strings.TrimSpace(filter)
	if !strings.HasPrefix(strings.ToLower(f), "username eq ") {
		return ""
	}
	return strings.Trim(strings.TrimSpace(f[len("username eq "):]), `"`)
}

func writeScimUser(w http.ResponseWriter, status int, name string, active bool) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scimUserBody(name, active))
}

func scimUserBody(name string, active bool) map[string]any {
	return map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":       name,
		"userName": name,
		"active":   active,
		"meta":     map[string]any{"resourceType": "User", "lastModified": time.Now().UTC().Format(time.RFC3339)},
	}
}
