# Design — transparent :53 redirect

## The loop, and the mark that breaks it

The redirect rule catches locally-generated UDP `dport 53` and sends it to the local resolver's high port.
But the resolver, to answer a *normal* (non-blocked) query, forwards it upstream — also to `dport 53`. That
forwarded packet is locally-generated too, so the same rule redirects it straight back into the resolver:
an infinite loop, and no query is ever answered.

The fix is a firewall mark. The resolver sets `SO_MARK = <mark>` on its upstream socket; the redirect rule
matches `udp dport 53 meta mark != <mark>`. Every client's `:53` traffic (mark 0) is redirected; the
resolver's own upstream leg (marked) is not — it reaches the real upstream. This is the same loop-break
dnscrypt-proxy / systemd-resolved use for transparent DNS. Both `SO_MARK` and the nft nat rule need
`CAP_NET_ADMIN`, so the whole path is root-gated and proven on the VM.

```
client ──udp/53──▶ [nat OUTPUT: dport 53, mark!=M → REDIRECT :PORT] ──▶ resolver(:PORT)
                                                                            │ blocked → NXDOMAIN ──▶ client
                                                                            │ allowed → forward (SO_MARK=M)
resolver ──udp/53, mark=M──▶ [rule skips marked] ──▶ real upstream ──▶ resolver ──▶ client
```

## `internal/dnssink` — the `Mark` field

`Resolver` gains `Mark int`. `forward` currently does `net.DialTimeout("udp", r.Upstream, ...)`. With
`Mark > 0` it instead dials through a `net.Dialer{Timeout, Control: markControl(r.Mark)}` where
`markControl` runs `unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)` inside the raw-conn
`Control` callback (linux). `Mark == 0` keeps the exact existing `net.DialTimeout` path, so every D231
forward/fail-open test is untouched. A `!linux` build-tagged `markControl` returns a control func that
errors (or is nil with Mark ignored) so the tree cross-compiles — Mark is only meaningful on linux where
the redirect lives.

Chosen: on `!linux`, `markControl` returns a non-nil control that fails loudly if ever invoked, but since
the redirect (and thus a non-zero Mark) is only wired on linux, the plain path runs everywhere else.

## `internal/dnsredirect` — install/remove (linux + stub)

Prefer nft; fall back to iptables. A dedicated table isolates our rules so cleanup is one delete and never
touches operator firewall state:

```
nft add table ip openshield_dnsredirect
nft add chain ip openshield_dnsredirect out { type nat hook output priority -100 \; }
nft add rule  ip openshield_dnsredirect out meta l4proto udp udp dport 53 meta mark != <mark> redirect to :<port>
```

- `Install(resolverPort, mark int) error` — **Remove-then-add** (the TPROXY idempotency discipline: delete
  any stale `openshield_dnsredirect` table first so a re-run never errors "exists"), then create table +
  chain + rule. Returns a clear error if neither nft nor iptables is available.
- `Remove() error` — `nft delete table ip openshield_dnsredirect` (ignore "no such table"); the iptables
  path deletes the single OUTPUT rule it added. Idempotent.
- The rule-argv construction is a **pure function** (`nftRuleArgs(port, mark)` / the iptables equivalent) so
  it is unit-testable without root: the test asserts the argv contains `dport 53`, the port, and the
  mark-exemption (`mark != <mark>` / `--mark`), and that Remove is the inverse.
- `!linux` stub: `Install`/`Remove` return `errUnsupported` ("transparent DNS redirect is linux-only") so
  the tree cross-compiles and the binary degrades cleanly.

## `cmd/openshield-gateway` wiring

Behind `OPENSHIELD_DNS_REDIRECT=1`, and only when the resolver is already configured
(`OPENSHIELD_DNS_SINK_LISTEN` set): parse the resolver's listen port, pick the mark
(`OPENSHIELD_DNS_REDIRECT_MARK`, default `0x1d5`), set `Resolver.Mark`, `dnsredirect.Install(port, mark)` on
startup, `Remove()` on shutdown. An nft/bind failure logs loudly and the gateway keeps running — the
resolver still serves explicitly-configured clients, just not transparently (fail-to-wire, never
fail-to-boot). Removing the redirect on shutdown matters: a left-behind rule pointing at a dead resolver
would wedge name resolution (the bypass watchdog that also covers a *crash* is the stated follow-up).

## Testing

- **(A) unit, no root** — `nftRuleArgs`/`iptablesRuleArgs` contain `dport 53`, the resolver port, and the
  mark-exemption; `Remove` argv is the inverse; the `!linux` stub returns the unsupported error.
- **(B) unit, no root** — `Resolver.Mark == 0` uses the plain dial path (existing forward tests unchanged);
  `Mark > 0` selects the control path (assert a non-nil dialer control is built; the actual `SetsockoptInt`
  is exercised only under the gated test).
- **(C) gated real-kernel VM test** (`requireRoot` + linux + nft/iptables present, else skip) —
  self-contained on loopback, no internet:
  1. a canned UDP "upstream" DNS responder on `127.0.0.2:53` answers a fixed A record;
  2. the `dnssink.Resolver` runs on a high port, `Upstream=127.0.0.2:53`, a `Mark`, `Blocked={evil.example}`;
  3. `Install(resolverPort, mark)`;
  4. a **client** raw-UDP query to `127.0.0.2:53` (as if that were its configured DNS — it never knows the
     resolver exists) for `evil.example` → **NXDOMAIN** (transparently sinkholed);
  5. a client query for `good.example` → the resolver forwards it (marked → escapes the redirect) to the
     real `127.0.0.2:53` upstream and relays the canned A answer.
  6. `Remove()` cleans up.

  **Mutation for (C):** the Install rule omits the mark-exemption (redirect *all* `dport 53`) → the
  resolver's own upstream forward loops back to itself → the `good.example` query never reaches the upstream
  → it times out with no answer → the test FAILs. Proves the loop-break is load-bearing, not decorative.

Build on the VM via `go test -c` + scp + `sudo ./dnsredirect.test`; paste the PASS. Locally the gated test
SKIPS (no root), like the execmon/TPROXY tests, so `make all` stays green.
