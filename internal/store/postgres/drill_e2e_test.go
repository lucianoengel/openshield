package postgres_test

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lucianoengel/openshield/internal/core"
	"github.com/lucianoengel/openshield/internal/store/postgres"
)

// PLAT-9: the restore drill, RUN rather than described.
//
// D277 shipped the drill's arguments and ordering with an honest caveat — no end-to-end
// backup→restore→verify ran, because this environment has no Postgres client tools. It has podman, so it
// has them: pg_dump/pg_restore come from the postgres image over the host network.
//
// What this proves that an argv test cannot:
//
//   - a real dump and restore PRESERVES A VERIFIABLE LEDGER. Not obvious: the chain commits to
//     microsecond-truncated timestamps, so any encoding that shifted them by a nanosecond would break
//     every entry on restore, and the argv test would still be green.
//   - a restored copy that LOST ITS WITNESSED TAIL is DETECTED. That is the whole reason the drill ends in
//     verification: a truncated ledger is internally consistent, and only the anchor catches it.

// pgWork is ONE shared directory bind-mounted into every tool invocation. A per-call temp directory would
// leave the dump invisible to the restore — a mistake worth not making silently.
type pgWork struct{ dir string }

// run executes a Postgres client tool from a container. It SKIPS (never fails) without podman, so
// `make all` stays green on a machine that lacks it — the same shape as the other environment-gated tests.
//
// AND IT SKIPS WHEN PODMAN IS PRESENT BUT CANNOT RUN ANYTHING, which the LookPath check alone does not
// cover and which cost a red build to diagnose. A GitHub runner shipped a podman whose OCI runtime was
// broken — `Error: OCI runtime error: crun: unknown version specified`, reproducible on that runner and
// absent on another in the same fleet — and this test reported `pg_dump: exit status 126`. That reads as a
// dump failure, i.e. as a defect in the ledger's backup story, when nothing had run at all.
//
// The distinction is kept narrow ON PURPOSE. Only a failure to START the container is an environment skip;
// a tool that ran and then failed still fails the test, because that is the drill actually being broken.
// Widening this to "any error is an environment problem" would delete the gate.
func (w pgWork) run(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman unavailable: the backup drill needs Postgres client tools")
	}
	full := append([]string{"run", "--rm", "--network=host",
		"-v", w.dir + ":/work:z", "docker.io/library/postgres:16"}, args...)
	out, err := exec.Command("podman", full...).CombinedOutput()
	if err != nil && containerDidNotStart(out) {
		t.Skipf("the container runtime cannot start a container, so the Postgres client tools are "+
			"unreachable — this is the environment, NOT the restore drill:\n%s", out)
	}
	return out, err
}

// containerDidNotStart reports whether podman failed before the tool ever ran. Matched on the runtime's
// own error text rather than on an exit code: 125/126/127 are suggestive but podman also returns the
// CONTAINER's status, so a tool that genuinely exits 126 would be indistinguishable from a runtime that
// could not exec it.
func containerDidNotStart(out []byte) bool {
	s := string(out)
	for _, marker := range []string{
		"OCI runtime error",
		"error creating container",
		"cannot set up namespace",
		"failed to mount",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func drillDSN(db string) string {
	return fmt.Sprintf("postgres://openshield:dev@127.0.0.1:55432/%s?sslmode=disable", db)
}

func TestRestoreDrillRunsEndToEnd(t *testing.T) {
	base := requireDB(t) // migrates, locks, and proves the server is reachable
	ctx := context.Background()
	work := pgWork{dir: t.TempDir()}

	// A scratch pair, so nothing here touches the database the other tests use.
	src, dst := "drill_src", "drill_dst"
	for _, db := range []string{src, dst} {
		_, _ = base.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, db))
		if _, err := base.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, db)); err != nil {
			t.Skipf("cannot create a scratch database (%v) — the drill needs one", err)
		}
		name := db
		t.Cleanup(func() {
			_, _ = base.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, name))
		})
	}

	// Seed the SOURCE with a real, ANCHORED ledger.
	srcPool, err := pgxpool.New(ctx, drillDSN(src))
	if err != nil {
		t.Fatal(err)
	}
	defer srcPool.Close()
	if err := postgres.Migrate(ctx, srcPool); err != nil {
		t.Fatal(err)
	}
	signer, err := core.NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	l, err := postgres.Open(ctx, drillDSN(src), signer)
	if err != nil {
		t.Skipf("cannot open a ledger on the scratch database: %v", err)
	}
	witness, err := core.NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	l.WitnessPub = witness.PublicKey()
	for i := 0; i < 5; i++ {
		if err := l.Append(ctx, entry(fmt.Sprintf("drill-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.AnchorHead(ctx, witness); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// BACK UP and RESTORE with the real tools, using the drill's own arguments.
	if out, err := work.run(t, "pg_dump", "--format=custom", "--no-owner", "--no-privileges",
		"--file=/work/openshield.dump", drillDSN(src)); err != nil {
		t.Fatalf("pg_dump: %v\n%s", err, out)
	}
	if out, err := work.run(t, "pg_restore", "--clean", "--if-exists", "--exit-on-error",
		"--no-owner", "--no-privileges", "--dbname="+drillDSN(dst), "/work/openshield.dump"); err != nil {
		t.Fatalf("pg_restore: %v\n%s", err, out)
	}

	// VERIFY THE RESTORE. This is the step the drill exists for.
	restored, err := postgres.OpenForVerify(ctx, drillDSN(dst))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	restored.WitnessPub = witness.PublicKey()
	res, err := restored.Verify(ctx, nil)
	if err != nil {
		t.Fatalf("verifying the restored ledger: %v", err)
	}
	if !res.Consistent {
		t.Fatalf("a restored ledger did not verify: %s — a round trip through pg_dump must preserve the "+
			"chain, or every restore is unprovable", res)
	}
	if res.Completeness != core.CompletenessAnchored {
		t.Errorf("restored completeness = %s, want anchored — the anchor rows must survive the dump, or "+
			"the restore can never be proven un-truncated", res.Completeness)
	}
	if res.Entries != 5 {
		t.Errorf("restored ledger has %d entries, want 5", res.Entries)
	}

	// AND THE FAILURE THE DRILL EXISTS TO CATCH: a restore that lost its witnessed tail. It is internally
	// consistent — it hashes perfectly and simply stops early — so only the anchor detects it.
	dstPool, err := pgxpool.New(ctx, drillDSN(dst))
	if err != nil {
		t.Fatal(err)
	}
	defer dstPool.Close()
	bypassAppendOnly(t, dstPool, `DELETE FROM audit_entries WHERE sequence >= 3`)

	truncated, err := postgres.OpenForVerify(ctx, drillDSN(dst))
	if err != nil {
		t.Fatal(err)
	}
	defer truncated.Close()
	truncated.WitnessPub = witness.PublicKey()
	res2, err := truncated.Verify(ctx, nil)
	if err != nil {
		t.Fatalf("verifying the truncated restore: %v", err)
	}
	if res2.Consistent {
		t.Fatal("a TRUNCATED restore verified as consistent — the exact failure the drill exists to " +
			"catch: the bytes came back, the evidence did not, and a procedure that reported success " +
			"here would report success on a lost tail")
	}
}
