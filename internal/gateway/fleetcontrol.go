package gateway

import (
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/intent"
	natsx "github.com/lucianoengel/openshield/internal/transport/nats"
)

// SubscribeFleetControl wires the GATEWAY to fleet-wide operational control (PLAT-9).
//
// The mirror of the engine's, and mirrored deliberately. core.KillSwitch's first stated property is "one
// implementation, consulted by BOTH enforcement call sites — a switch honoured by the gateway and
// forgotten by the endpoint is worse than none, because the operator believes enforcement stopped and it
// did not". Until this the endpoint had a way to be reached fleet-wide and the gateway did not, which is
// that failure with the components swapped.
//
// The subscriber verifies the signature, refuses a replayed sequence, and refuses an expired or
// unknown-version control. Everything it refuses leaves enforcement ON.
//
// bound persists the replay sequence across restarts (SEC-B); nil keeps it in memory and the caller owes
// the operator a startup warning saying so.
func (g *Gateway) SubscribeFleetControl(conn *nats.Conn, key ed25519.PublicKey,
	bound natsx.SeqStore) (*nats.Subscription, error) {
	if g.KillSwitch == nil {
		return nil, errors.New("gateway: no kill switch installed; refusing to accept fleet control that " +
			"would have nothing to act on")
	}
	var sub *intent.FleetControlSubscriber
	if bound == nil {
		sub = intent.NewFleetControlSubscriber(key, g.KillSwitch)
	} else {
		var err error
		if sub, err = intent.NewPersistentFleetControlSubscriber(key, g.KillSwitch, bound); err != nil {
			return nil, err
		}
	}
	g.fleetControl = sub
	return sub.Subscribe(conn)
}

// FleetControlCounts reports controls APPLIED and REJECTED by the fleet-control channel. The subscriber
// used to be constructed and discarded above, so its counters were unreachable (D418).
func (g *Gateway) FleetControlCounts() (applied, rejected int64) {
	if g.fleetControl == nil {
		return 0, 0
	}
	return g.fleetControl.Applied.Load(), g.fleetControl.Rejected.Load()
}
