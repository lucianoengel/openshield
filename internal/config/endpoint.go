package config

// Endpoint configuration (PLAT-5 follow-up).
//
// ALL BOOTSTRAP, for a stronger reason than the gateway's: the privileged agent and the sandboxed worker
// must not reach a database at all. The agent's dependency ban (check-agent-deps.sh) exists because it
// never parses attacker-controlled bytes, and the worker's seccomp filter DENIES network. A config layer
// that needed either would be unusable in both.
//
// This package is stdlib-only by construction, which is what makes it usable HERE — the same declarations,
// the same derived schema, the same fail-at-boot validation, in the two components where a silently
// defaulted value is most dangerous. `make all` proves the boundary holds.

// AgentFields declares what cmd/openshield-agent reads: the privileged exec gate's configuration.
//
// Note what the DEFAULTS say about the design: with nothing set the agent monitors nothing, and with
// monitoring on but no signal configured it refuses to start rather than watching and permitting
// everything. A security component that silently does nothing is the failure mode these declarations make
// visible.
var AgentFields = []Field{
	{Key: "OPENSHIELD_EXEC_MONITOR_DIRS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Comma-separated paths the exec monitor watches (HIPS-3). Unset means no exec monitoring at all."},
	// B2 — the inline file-open gate. Separate from the exec gate's settings on purpose: the two have
	// very different availability costs, and an operator may reasonably want one without the other.
	{Key: "OPENSHIELD_OPEN_GATE_DIRS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Comma-separated DIRECTORIES whose file opens are decided inline (B2). Directories only — a mount-wide scope is refused, because every open on the host would then enter a permission window. Unset disables the gate."},
	{Key: "OPENSHIELD_OPEN_IPC_SOCKET", Scope: ScopeBootstrap, Kind: KindSocketPath, Default: "",
		Description: "Socket the engine answers file-open verdicts on. REQUIRED when the gate is enabled: there is no local fallback, so without it the gate would fail open on every event while reporting itself active."},
	{Key: "OPENSHIELD_OPEN_IPC_TIMEOUT", Scope: ScopeBootstrap, Kind: KindDuration, Default: "150ms",
		Description: "Bound on one verdict round trip. Must sit inside the watchdog budget — a client still waiting when the budget elapses is producing an answer nobody can use."},
	{Key: "OPENSHIELD_OPEN_BUDGET", Scope: ScopeBootstrap, Kind: KindDuration, Default: "500ms",
		Description: "How long a process may be held in a file-open permission window before the watchdog ALLOWS and audits. This is the host's safety margin, not a tuning knob."},
	{Key: "OPENSHIELD_EXEC_DENY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Deny-list file of binaries refused at exec."},
	{Key: "OPENSHIELD_EXEC_ALLOW", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Application whitelist: the ONLY binaries permitted to exec (default-deny). Stronger than a deny list and mutually informative with it."},
	{Key: "OPENSHIELD_EXEC_BEHAVIOR_FLOOR", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Behavioral score at or above which an exec is refused."},
	{Key: "OPENSHIELD_EXEC_IPC_SOCKET", Scope: ScopeBootstrap, Kind: KindSocketPath, Default: "",
		Description: "Socket the exec gate asks the unprivileged engine over. Unset means no policy-backed verdicts. Not required to exist at startup: the engine creates it, and a gate that refused to start without it would fail CLOSED for the exact outage it fails OPEN for."},
	{Key: "OPENSHIELD_EXEC_IPC_TIMEOUT", Scope: ScopeBootstrap, Kind: KindDuration, Default: "",
		Description: "How long the exec gate waits for a verdict before falling back. Fail-open by design (D17): a dead engine must not wedge every exec on the host."},
	{Key: "OPENSHIELD_EXEC_BUDGET", Scope: ScopeBootstrap, Kind: KindDuration, Default: "500ms",
		Description: "Total time budget for an exec decision. Exceeding it allows the exec, loudly."},
}

// WorkerFields declares what cmd/openshield-worker reads: the sandboxed parser's indexes and rules.
//
// Almost all of it is a PATH to something signed, which is the shape of this component: it loads operator
// data into the process that parses untrusted bytes, so every input has a verification story
// (OPENSHIELD_DLP_INDEX_PUBKEY, OPENSHIELD_RULES_PUBKEY) and the unverified paths are warned about.
var WorkerFields = []Field{
	{Key: "OPENSHIELD_EDM_INDEX", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Exact-data-match index of sensitive values."},
	{Key: "OPENSHIELD_EDM_RECORD_INDEX", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Exact-data-match RECORD index (multi-field records)."},
	{Key: "OPENSHIELD_IDM_INDEX", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Indexed-document-match index for document fingerprinting."},
	{Key: "OPENSHIELD_DLP_INDEX_PUBKEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Public key DLP indexes are verified against (ADR-9). Unset loads indexes UNVERIFIED, which is warned about at load."},
	{Key: "OPENSHIELD_NIPS_RULES", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Content-signature rules (NIPS-2). Unset leaves body-content matching OFF."},
	{Key: "OPENSHIELD_RULES_BUNDLE", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Signed custom detection-rule bundle (HON-1/D100)."},
	{Key: "OPENSHIELD_RULES_PUBKEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Operator public key the rule bundle is verified against. A bundle set without this is REFUSED \u2014 loading is fail-closed."},
}
