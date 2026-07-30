//go:build integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// A TRUE NETWORK PARTITION OF THE ENDPOINT, which is not the same thing as a broker outage.
//
// Every other outage scenario here takes the BROKER away. That covers "the other end went down", and it is
// the outage most often written about. It does not cover what an endpoint actually does far more often: ITS
// OWN network disappears. A closed laptop, a dropped VPN, a radio switched off, a container detached.
//
// The two differ in ways that can break code which handles the first cleanly:
//
//   - The interface is GONE, so a write fails with ENETUNREACH/EHOSTUNREACH rather than the connection
//     refused that a stopped broker produces.
//   - DNS goes with it, so the broker's NAME stops resolving. A client that only re-dials a cached address
//     behaves differently from one that re-resolves.
//   - On rejoin the endpoint gets a DIFFERENT IP. Anything that assumed its own address survives the outage
//     is wrong, and this is the normal case rather than a corner.
//
// The enterprise gap assessment named this as one of four properties a single-host fleet topology cannot
// exercise. It needs a real network namespace, which means a container.
//
// WHY THE AGENT ENROLS ON THE HOST FIRST. The container would otherwise have to reach the control plane's
// enrolment endpoint, which binds 127.0.0.1 — so the test would need to bind it to 0.0.0.0 and widen a
// listener on the developer's machine for the duration of a run. Instead the agent enrols as a host
// process, persists its identity (D318), and the CONTAINER starts with that identity and NO TOKEN. That is
// a stronger starting point anyway: an agent that needs a token to come back has been re-provisioned
// rather than restarted.

const alpineImage = "docker.io/library/alpine:3"

// staticAgent builds the fleet agent with cgo disabled, because the harness's binary is dynamically linked
// against the host's libc and a minimal image has none.
func staticAgent(t *testing.T, dir string) string {
	t.Helper()
	out := filepath.Join(dir, "openshield-fleet-agent")
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, "./cmd/openshield-fleet-agent/")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building a static fleet agent: %v\n%s", err, o)
	}
	return out
}

// podmanOK skips unless the runtime can actually START a container. `podman --version` succeeding is not the
// same thing — a CI runner shipped a podman whose OCI runtime could not run anything ("crun: unknown
// version specified"), and a presence check there lets every scenario skip while reporting success.
func podmanOK(t *testing.T) {
	t.Helper()
	requirePodman(t)
	if out, err := exec.Command("podman", "run", "--rm", alpineImage, "true").CombinedOutput(); err != nil {
		t.Skipf("the container runtime cannot start a container, so a partition cannot be simulated: %v\n%s",
			err, out)
	}
}

// TestAnEndpointSurvivesItsOwnNetworkVanishing partitions the AGENT, not the broker.
func TestAnEndpointSurvivesItsOwnNetworkVanishing(t *testing.T) {
	podmanOK(t)
	stack := StartStack(t)
	work := t.TempDir()
	spool := filepath.Join(work, "spool")
	identity := filepath.Join(work, "identity.key")

	const agentID = "agent-partitioned"

	// A NETWORK THE AGENT CAN BE REMOVED FROM, AND A BROKER ON IT.
	//
	// The stack's own broker cannot be reused: the harness starts it in the default rootless network mode,
	// and `podman network connect` refuses that outright — `"slirp4netns" is not supported: invalid network
	// mode`. So this scenario brings up its own broker ON the bridge network, published to a host port so
	// the control plane (a host process) still reaches it on 127.0.0.1, while the AGENT reaches it BY NAME
	// over the bridge. That is what puts DNS inside the partition rather than beside it.
	netName := containerPrefix + "part-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 10)
	run(t, "podman", "network", "create", netName)
	t.Cleanup(func() { _ = exec.Command("podman", "network", "rm", "-f", netName).Run() })

	brokerCtr := uniqueName(t, "partnats")
	brokerPort := freePort(t)
	run(t, "podman", "run", "-d", "--rm", "--name", brokerCtr, "--network", netName,
		"-p", "127.0.0.1:"+brokerPort+":4222", natsImage, "-js")
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", brokerCtr).Run() })
	waitTCP(t, "127.0.0.1:"+brokerPort, 60*time.Second)
	brokerHostURL := "nats://127.0.0.1:" + brokerPort

	// The control plane consumes from the PARTITION broker. extraEnv is appended last, so this wins over
	// the stack's own URL.
	_, enrollURL := startServer(t, stack, "OPENSHIELD_NATS_URL="+brokerHostURL)
	pool := openPool(t, stack.DSN)

	// ENROL ON THE HOST, then stop. Only the identity travels into the container.
	token := issueToken(t, stack, agentID)
	hostAgent := Start(t, "openshield-fleet-agent", []string{
		"OPENSHIELD_AGENT_ID=" + agentID,
		"OPENSHIELD_ENROLL_URL=" + enrollURL,
		"OPENSHIELD_ENROLL_TOKEN=" + token,
		"OPENSHIELD_NATS_URL=" + brokerHostURL,
		"OPENSHIELD_IDENTITY_FILE=" + identity,
		"OPENSHIELD_HEARTBEAT=500ms",
	})
	hostAgent.WaitForOutput("enrolled", 90*time.Second)
	hostAgent.Stop()
	if _, err := os.Stat(identity); err != nil {
		t.Fatalf("the identity was not persisted, so the container would have to re-enrol: %v", err)
	}

	// THE AGENT IN A CONTAINER, with no token — it has an identity.
	bin := staticAgent(t, work)
	agentCtr := uniqueName(t, "partagent")
	run(t, "podman", "run", "-d", "--rm", "--name", agentCtr,
		"--network", netName,
		"-v", bin+":/openshield-fleet-agent:ro,Z",
		"-v", work+":/state:z",
		"-e", "OPENSHIELD_AGENT_ID="+agentID,
		"-e", "OPENSHIELD_NATS_URL=nats://"+brokerCtr+":4222",
		"-e", "OPENSHIELD_IDENTITY_FILE=/state/identity.key",
		"-e", "OPENSHIELD_QUEUE_DIR=/state/spool",
		"-e", "OPENSHIELD_SEQ_FILE=/state/seq",
		"-e", "OPENSHIELD_HEARTBEAT=500ms",
		alpineImage, "/openshield-fleet-agent")
	t.Cleanup(func() { _ = exec.Command("podman", "rm", "-f", agentCtr).Run() })
	ctrLog := func() string {
		out, _ := exec.Command("podman", "logs", agentCtr).CombinedOutput()
		return string(out)
	}

	rows := func() int {
		var n int
		if err := pool.QueryRow(Ctx(t),
			`SELECT count(*) FROM fleet_telemetry WHERE agent_id = $1`, agentID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	baseline := rows()
	Eventually(t, 120*time.Second, "the containerised agent's telemetry to arrive", func() bool {
		return rows() > baseline
	})
	addrBefore := containerIP(t, agentCtr)
	t.Logf("agent running in a container at %s", addrBefore)

	// THE PARTITION. Not a stopped broker — the agent's own interface is removed.
	run(t, "podman", "network", "disconnect", netName, agentCtr)
	t.Log("agent partitioned: its interface is gone, and with it DNS for the broker")

	Eventually(t, 90*time.Second, "the partitioned agent to spool", func() bool {
		return spoolFiles(t, spool) > 0
	})
	time.Sleep(8 * time.Second)
	held := spoolFiles(t, spool)
	before := rows()
	if held == 0 {
		t.Fatalf("a partitioned agent spooled nothing\n%s", ctrLog())
	}
	t.Logf("partitioned: %d record(s) held, %d row(s) stored", held, before)

	// REJOIN, ON A DIFFERENT ADDRESS — podman assigns a new IP, which is the realistic case and the one an
	// agent that cached its own address would get wrong.
	run(t, "podman", "network", "connect", netName, agentCtr)
	t.Logf("agent rejoined at %s (was %s)", containerIP(t, agentCtr), addrBefore)

	drained := false
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		if spoolFiles(t, spool) == 0 {
			drained = true
			break
		}
		time.Sleep(time.Second)
	}
	if !drained {
		t.Fatalf("the spool did not drain after the agent's network came back (%d record(s) still held). "+
			"The agent's own log is the evidence here — a partition is not a broker outage, and a client "+
			"that recovers from the second need not recover from the first:\n%s",
			spoolFiles(t, spool), ctrLog())
	}
	want := before + held
	Eventually(t, 120*time.Second, "the records held across the partition to be STORED", func() bool {
		return rows() >= want
	})
	t.Logf("recovered across a partition: %d row(s) stored (held %d)\n%s", rows(), held, ctrLog())
}

// containerIP reports a container's addresses, or "" when it has none — which is what a partitioned
// container looks like, and is why this is best-effort rather than fatal.
func containerIP(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("podman", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}
