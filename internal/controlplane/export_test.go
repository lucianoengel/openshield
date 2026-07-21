package controlplane

import "net/http"

// RequireRoleForTest exposes the unexported role gate to the external test
// package, wrapping a handler that writes 200 on success — so a test can assert
// the 401/403/200 outcomes directly.
func RequireRoleForTest(role string) http.Handler {
	return requireRole(role, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}
