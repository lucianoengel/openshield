// Command openshield-agent is the DEFERRED privileged inline-enforcement agent.
//
// It is NOT the observe path: the observe pipeline runs unprivileged as
// openshield-engine, which opens fanotify in NOTIFY mode itself (D52). This agent
// exists for INLINE BLOCKING — fanotify PERMISSION mode, which answers an
// open/read while a process is parked in TASK_UNINTERRUPTIBLE and needs
// CAP_SYS_ADMIN. That path is deferred to Phase 2 (D49): classification cannot
// complete inside the 532µs permission-window budget (T-002), so OpenShield
// contains after detection rather than blocking inline. This binary is a
// placeholder for that future component; it does no work yet.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr,
		"openshield-agent: the privileged inline-blocking agent (fanotify PERMISSION mode) is "+
			"DEFERRED to Phase 2 (D49). For the observe path, run openshield-engine "+
			"(unprivileged, OPENSHIELD_WATCH_DIRS). This binary does nothing yet.")
	// Exit non-zero so a service manager does not treat a do-nothing stub as a
	// healthy running agent.
	os.Exit(2)
}
