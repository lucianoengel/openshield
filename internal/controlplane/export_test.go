package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lucianoengel/openshield/internal/notify"
)

// NewLeaderForTest builds a Leader with a fast poll interval so the election/failover test runs
// quickly (PLAT-2b).
func NewLeaderForTest(pool *pgxpool.Pool, poll time.Duration) *Leader {
	return &Leader{pool: pool, key: leaderLockKey, poll: poll}
}

// RequireRoleForTest exposes the unexported role gate to the external test
// package, wrapping a handler that writes 200 on success — so a test can assert
// the 401/403/200 outcomes directly.
func RequireRoleForTest(role string) http.Handler {
	return requireRole(role, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// RequireTierForTest exposes the tiered RBAC gate (PLAT-3) so a test can assert the
// 401/403/200 outcomes of a minimum-tier requirement directly.
func RequireTierForTest(minRole string) http.Handler {
	return requireTier(minRole, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// EmitForTest exposes the unexported emit so a test can prove an unconfigured server
// never fills its notify queue (R34-9).
func (s *Server) EmitForTest(n notify.Notification) { s.emit(context.Background(), n) }
