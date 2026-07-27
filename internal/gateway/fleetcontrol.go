package gateway

import (
	"crypto/ed25519"
	"errors"

	"github.com/nats-io/nats.go"

	"github.com/lucianoengel/openshield/internal/intent"
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
func (g *Gateway) SubscribeFleetControl(conn *nats.Conn, key ed25519.PublicKey) (*nats.Subscription, error) {
	if g.KillSwitch == nil {
		return nil, errors.New("gateway: no kill switch installed; refusing to accept fleet control that " +
			"would have nothing to act on")
	}
	return intent.NewFleetControlSubscriber(key, g.KillSwitch).Subscribe(conn)
}
