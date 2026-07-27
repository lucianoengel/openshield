package config

// The remaining endpoint binaries (PLAT-5 follow-up, completing the adoption).
//
// BOOTSTRAP-ONLY, and here the reason is a CONSISTENCY requirement rather than a capability one. The
// engine can reach Postgres — it writes the forward-secure ledger — so it COULD technically read dynamic
// settings. It must not, because D269 built an entire signed fleet-control channel on the premise that
// ENDPOINTS DO NOT READ THE CONFIGURATION STORE. Making engine settings dynamic would quietly invalidate
// that justification and leave two disagreeing answers to "how does an endpoint learn something
// fleet-wide". One answer, on the signed channel, verified.

// EngineFields declares what cmd/openshield-engine reads: the endpoint pipeline's sources and enforcers.
//
// Read as a group they describe the endpoint's posture. Almost every detection source is OFF by default —
// FIM, canaries, memory scanning, clipboard, DNS — and enforcement requires OPENSHIELD_ENFORCE on top of a
// policy that asks for it (D1). The defaults are the observe-only ones, so a deployment that configures
// nothing watches its directories and breaks nothing.
var EngineFields = []Field{
	{Key: "OPENSHIELD_DSN", Scope: ScopeBootstrap, Kind: KindString, Default: "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable",
		Description: "Postgres connection for this endpoint's forward-secure ledger (D30)."},
	{Key: "OPENSHIELD_AGENT_ID", Scope: ScopeBootstrap, Kind: KindString, Default: "engine",
		Description: "Identity this engine enrolls and signs telemetry under."},
	{Key: "OPENSHIELD_WORKER_BIN", Scope: ScopeBootstrap, Kind: KindPath, Default: "/usr/local/bin/openshield-worker",
		Description: "Sandboxed parser worker. Content is classified there, never in this process (D29)."},
	{Key: "OPENSHIELD_SIGNER_FILE", Scope: ScopeBootstrap, Kind: KindString, Default: "/var/lib/openshield/signer.state",
		Description: "Forward-secure ledger signer state. Its directory must survive restarts or the chain cannot continue."},
	{Key: "OPENSHIELD_SEQ_FILE", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Persisted telemetry sequence. Without it a restart replays sequence numbers and the control plane sees a gap."},
	{Key: "OPENSHIELD_NATS_URL", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "NATS URL for telemetry. Set with an enrollment URL to publish signed."},
	{Key: "OPENSHIELD_ENROLL_URL", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Control-plane enrollment endpoint."},
	{Key: "OPENSHIELD_ENROLL_TOKEN", Scope: ScopeBootstrap, Kind: KindSecret, Default: "",
		Description: "Single-use enrollment token (D44)."},
	{Key: "OPENSHIELD_CONTROL_PLANE_KEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "File holding the ed25519 PUBLIC key that signed fleet-wide controls are verified against (PLAT-9). Unset means this host accepts no fleet control and can only be stopped locally."},
	{Key: "OPENSHIELD_BREAK_GLASS", Scope: ScopeBootstrap, Kind: KindString, Default: "/etc/openshield/EMERGENCY_DISABLE",
		Description: "Local break-glass file. While it EXISTS, this host stops ENFORCING but keeps detecting and auditing \u2014 the answer to \"how do I stop this\" when the control plane is unreachable."},
	{Key: "OPENSHIELD_BREAK_GLASS_POLL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "10s",
		Description: "How often the break-glass file is checked. Short: this is the emergency path, and a slow one is not one."},
	{Key: "OPENSHIELD_ENFORCE", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Set to register the file enforcers. Unset is observe-only (D1)."},
	{Key: "OPENSHIELD_RETENTION_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "24h",
		Description: "How often this endpoint purges its aggregate under the retention window."},
	{Key: "OPENSHIELD_WATCH_DIRS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Comma-separated directories to watch. At least one is required \u2014 the engine refuses to start watching nothing."},
	{Key: "OPENSHIELD_POLICY_PACK", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Compliance policy pack(s) to load (DLP-5b)."},
	{Key: "OPENSHIELD_POLICY_CUSTOM", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Optional custom policy layered over the packs."},
	{Key: "OPENSHIELD_QUARANTINE_DIR", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Directory quarantined files are moved to."},
	{Key: "OPENSHIELD_ENCRYPT_KEY", Scope: ScopeBootstrap, Kind: KindSecret, Default: "",
		Description: "Key for local encryption enforcement."},
	{Key: "OPENSHIELD_ENCRYPT_PUBKEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Public key for local encryption enforcement."},
	{Key: "OPENSHIELD_DNS_LISTEN", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Address for the DNS query connector (NIPS-3). Empty disables it."},
	{Key: "OPENSHIELD_EXEC_AUDIT_LOG", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "auditd log the exec connector reads (HIPS-5c). Additive and observe-only unless a KILL policy and OPENSHIELD_ENFORCE are both set."},
	{Key: "OPENSHIELD_EXEC_IPC_SOCKET", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Socket this engine answers the privileged exec gate on. It serves verdicts; it does not ask for them."},
	{Key: "OPENSHIELD_FIM_PATHS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Critical files/dirs to monitor for integrity (HIPS-4). Unset leaves FIM inert."},
	{Key: "OPENSHIELD_FIM_BASELINE", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Known-good manifest FIM compares against. Required when FIM paths are set."},
	{Key: "OPENSHIELD_FIM_BASELINE_PUBKEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Key the FIM baseline is verified against. Unset loads the baseline UNSIGNED, which is warned about \u2014 an unsigned baseline is one an attacker can rewrite."},
	{Key: "OPENSHIELD_FIM_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "60s",
		Description: "How often FIM re-hashes its paths."},
	{Key: "OPENSHIELD_FIM_REALTIME", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Set to watch FIM paths for changes rather than only polling."},
	{Key: "OPENSHIELD_FIM_DEBOUNCE", Scope: ScopeBootstrap, Kind: KindDuration, Default: "200ms",
		Description: "How long real-time FIM coalesces rapid changes before hashing."},
	{Key: "OPENSHIELD_CANARY_DIRS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Directories seeded with ransomware canary files. Unset leaves the canary inert."},
	{Key: "OPENSHIELD_CANARY_COUNT", Scope: ScopeBootstrap, Kind: KindInt, Default: "16",
		Description: "How many canaries per directory."},
	{Key: "OPENSHIELD_CANARY_THRESHOLD", Scope: ScopeBootstrap, Kind: KindInt, Default: "4",
		Description: "Canary touches within the window that raise a detection."},
	{Key: "OPENSHIELD_CANARY_WINDOW", Scope: ScopeBootstrap, Kind: KindDuration, Default: "10s",
		Description: "Window the canary threshold is counted over."},
	{Key: "OPENSHIELD_CANARY_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "2s",
		Description: "How often canaries are checked."},
	{Key: "OPENSHIELD_USB_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "0s",
		Description: "How often attached USB devices are enumerated (T-020). Zero disables USB observation. Polling cannot miss a device that stays attached; it can miss one attached and removed between two ticks."},
	{Key: "OPENSHIELD_USB_ENFORCE", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Set to register the USB posture enforcer (T-020). It writes authorized_default on every USB controller, so a BLOCK deauthorises EVERY subsequently attached device including keyboards — the kernel switch is per-controller, not per-device. Needs root. Separate from OPENSHIELD_ENFORCE because it changes how the whole machine treats new hardware."},
	{Key: "OPENSHIELD_USB_SYSFS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Override for the sysfs USB root. Empty uses /sys/bus/usb/devices; set only to point at a fixture tree."},
	{Key: "OPENSHIELD_USB_PSEUDONYM_KEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Key file that pseudonymises USB serials (D23). Unset generates an EPHEMERAL key, so pseudonyms are stable only for one process lifetime and the same device reads as new after a restart."},
	{Key: "OPENSHIELD_MEMSCAN_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "0s",
		Description: "How often to scan for memory injection. 0 disables it."},
	{Key: "OPENSHIELD_CLIPBOARD_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "0s",
		Description: "How often to poll the clipboard. 0 disables clipboard DLP."},
	{Key: "OPENSHIELD_CLIPBOARD_EXCLUDE", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Applications whose copies are never read \u2014 password managers and the like. Exclusions are applied BEFORE the read."},
	{Key: "OPENSHIELD_CLIPBOARD_MEDIATE", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Set to MEDIATE the X11 clipboard rather than observe it: owning the selection gives per-destination enforcement."},
	{Key: "OPENSHIELD_PRINT_SOCKET", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Socket the CUPS print filter asks for print verdicts on."},
}

// FleetAgentFields declares what cmd/openshield-fleet-agent reads: enrollment, publication and posture.
var FleetAgentFields = []Field{
	{Key: "OPENSHIELD_AGENT_ID", Scope: ScopeBootstrap, Kind: KindString, Default: "fleet-agent",
		Description: "Identity this fleet agent enrolls under."},
	{Key: "OPENSHIELD_ENROLL_URL", Scope: ScopeBootstrap, Kind: KindString, Default: "http://127.0.0.1:8080/enroll",
		Description: "Control-plane enrollment endpoint."},
	{Key: "OPENSHIELD_ENROLL_TOKEN", Scope: ScopeBootstrap, Kind: KindSecret, Default: "",
		Description: "Single-use enrollment token (D44)."},
	{Key: "OPENSHIELD_NATS_URL", Scope: ScopeBootstrap, Kind: KindString, Default: "nats://127.0.0.1:4222",
		Description: "NATS URL telemetry is published to."},
	{Key: "OPENSHIELD_SUBJECT", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Pseudonymous subject shaping generated telemetry. Access decisions key on the ENROLLED identity, not this."},
	{Key: "OPENSHIELD_HEARTBEAT", Scope: ScopeBootstrap, Kind: KindDuration, Default: "2s",
		Description: "Heartbeat interval. Absence of a heartbeat is what makes a missing agent detectable (D16)."},
	{Key: "OPENSHIELD_BURST", Scope: ScopeBootstrap, Kind: KindInt, Default: "1",
		Description: "Events generated per tick."},
	{Key: "OPENSHIELD_SEQ_FILE", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Persisted sequence. Without it a restart replays sequence numbers and the control plane sees a gap."},
	{Key: "OPENSHIELD_IDENTITY_FILE", Scope: ScopeBootstrap, Kind: KindOutputPath, Default: "",
		Description: "Where the agent keeps its signing key. Set it so the agent survives a restart: without it a new keypair is generated each boot, and because enrollment tokens are single-use and SEC-2 refuses to replace an enrolled agent's key, every restart needs a fresh operator-issued token. Written 0600; a key file readable by others is refused."},
	{Key: "OPENSHIELD_JETSTREAM", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Set to 0 to opt OUT of durable ingest, accepting AT-MOST-ONCE delivery on a broker without JetStream."},
	{Key: "OPENSHIELD_QUEUE_DIR", Scope: ScopeBootstrap, Kind: KindOutputPath, Default: "",
		Description: "Spool directory for offline queueing. Unset means events are dropped while the broker is unreachable."},
	{Key: "OPENSHIELD_QUEUE_MAX", Scope: ScopeBootstrap, Kind: KindInt, Default: "10000",
		Description: "Maximum spooled events before the oldest are dropped."},
	{Key: "OPENSHIELD_POSTURE_SIGNING_KEY", Scope: ScopeBootstrap, Kind: KindPath, Default: "",
		Description: "Signing key for opt-in device-posture reporting (HON-4). Unset means no posture is reported."},
	{Key: "OPENSHIELD_ENROLL_PREAUTH_TOKEN", Scope: ScopeBootstrap, Kind: KindSecret, Default: "",
		Description: "A single-use pre-authorization token issued by the operator, presented when self-enrolling an attestation key. Required only when the gateway sets OPENSHIELD_ENROLL_PREAUTH_TOKENS; ignored otherwise, so one agent configuration serves both."},
	{Key: "OPENSHIELD_ATTEST_SELF_ENROLL", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "Set to have the agent enrol its attestation key with the gateway over the network (ZT-1), proving the AK is TPM-resident by credential activation. Opt-in because a device asserting its own identity to the control plane is what OPENSHIELD_ENROLL_PREAUTH_TOKENS and OPENSHIELD_EK_ROOTS exist to constrain. The alternative is an operator-captured file: openshield-provision attest-capture."},
	{Key: "OPENSHIELD_ATTEST_PCRS", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "TPM PCRs to quote. Unset disables attestation."},
	{Key: "OPENSHIELD_TPM_ADDR", Scope: ScopeBootstrap, Kind: KindString, Default: "",
		Description: "TPM device or simulator address."},
	{Key: "OPENSHIELD_ATTEST_INTERVAL", Scope: ScopeBootstrap, Kind: KindDuration, Default: "5m",
		Description: "How often a fresh attestation quote is produced."},
}

// ToolFields are the operator tools' settings (PLAT-5 follow-up).
//
// Small, and worth declaring for the same reason as the rest: a setting no schema knows about is one no
// interface can ever show. Three of the other tools were flagged by the coverage guard and turned out to
// read NOTHING — they only tell an operator which variable to set elsewhere — which is why the guard now
// matches call forms rather than every mention of a name.
var AnchorFields = []Field{
	{Key: "OPENSHIELD_DSN", Scope: ScopeBootstrap, Kind: KindString,
		Default:     "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable",
		Description: "Postgres connection for the ledger being anchored."},
	{Key: "OPENSHIELD_WITNESS_KEY", Scope: ScopeBootstrap, Kind: KindSecret,
		Description: "Witness private key that signs anchors (T-019). The witness is what makes truncation detectable, so this key is the anchor chain's trust root."},
}

// PrintFilterFields is what the CUPS filter reads. One setting, because everything else about a print job
// comes from CUPS itself.
var PrintFilterFields = []Field{
	{Key: "OPENSHIELD_PRINT_SOCKET", Scope: ScopeBootstrap, Kind: KindPath,
		Description: "Socket the filter asks the engine for a print verdict on. Unset means the filter passes every job through — fail-open, because a DLP that breaks printing gets uninstalled (D17)."},
}

// CtlFields is what the operator CLI reads. Everything else is a flag, deliberately: a command an
// operator types should say what it is doing in the command line, not in the environment.
var CtlFields = []Field{
	{Key: "OPENSHIELD_DSN", Scope: ScopeBootstrap, Kind: KindString,
		Default:     "postgres://openshield:dev@127.0.0.1:55432/openshield?sslmode=disable",
		Description: "Postgres connection the CLI reads. Overridden by --dsn."},
}
