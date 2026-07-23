package gateway

import (
	"context"
	"log/slog"
	"net"
)

// RunTProxyWithRules installs the self-owned TPROXY redirect rules, runs the transparent inline server, and
// removes the rules the instant Serve returns — for ANY reason (an unexpected listener/accept stop as well
// as a clean ctx cancel). This binds the rules' lifetime to the SERVER's lifetime: a stopped listener never
// leaves forwarded traffic redirected into a dead socket (the D73/D17 fail-open invariant applied to the
// redirect — a redirect must not outlive the thing it redirects into). Blocks until Serve returns; call it
// in a goroutine.
func RunTProxyWithRules(ctx context.Context, ln net.Listener, srv *TProxyServer, port int, dports []int, mark, table int, log *slog.Logger) {
	runTProxyWithRules(ctx,
		func(c context.Context) error { return srv.Serve(c, ln) },
		func() error { return InstallTProxyRules(port, dports, mark, table, log) },
		func() { _ = RemoveTProxyRules(port, dports, mark, table, log) },
		log)
}

// runTProxyWithRules is the seam-injected core (testable without root): install, serve, then remove ONLY if
// install succeeded, on EVERY serve return.
func runTProxyWithRules(ctx context.Context, serve func(context.Context) error, install func() error, remove func(), log *slog.Logger) {
	installed := install() == nil
	if !installed && log != nil {
		log.Error("gateway: TPROXY rules could NOT install — inline plane still runs (install rules out of " +
			"band; needs CAP_NET_ADMIN + iptables/ip)")
	}
	serveErr := serve(ctx)
	if installed {
		remove() // rules never outlive the server — removed the instant Serve returns
	}
	if serveErr != nil && ctx.Err() == nil && log != nil {
		log.Error("gateway: TPROXY inline server stopped UNEXPECTEDLY — redirect rules removed, traffic falls "+
			"back to direct routing (fail-open)", slog.String("err", serveErr.Error()))
	}
}
