package controlplane_test

import (
	"testing"
	"time"

	"github.com/lucianoengel/openshield/internal/controlplane"
)

// SEC-10: two "startups" (EnablePeerUEBA on fresh Server instances sharing the DB) reserve
// disjoint context-version blocks, so their versions never collide across a restart (D27).
func TestContextVersionDoesNotCollideAcrossRestarts(t *testing.T) {
	pool := requireDB(t)

	observe3 := func(srv *controlplane.Server) string {
		// Feed 3 subjects so a peer baseline exists, then read subject-a's context version.
		for _, id := range []string{"sub-a", "sub-b", "sub-c"} {
			srv.ObserveForTest(id)
		}
		return srv.CurrentContextVersion("sub-a")
	}

	srv1 := controlplane.New(pool)
	srv1.EnablePeerUEBA(0.5, time.Hour) // "startup 1" reserves a version block
	v1 := observe3(srv1)

	srv2 := controlplane.New(pool)
	srv2.EnablePeerUEBA(0.5, time.Hour) // "restart" reserves the NEXT block
	v2 := observe3(srv2)

	if v1 == "" || v2 == "" {
		t.Fatalf("empty context version(s): %q / %q", v1, v2)
	}
	if v1 == v2 {
		t.Errorf("context_version collided across restarts: %q == %q — D27 attribution is ambiguous (SEC-10)", v1, v2)
	}
}
