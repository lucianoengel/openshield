# enforcement delta

## ADDED Requirements

### Requirement: The socket-backed flow table carries a verdict as a disposition the handler applies
The socket-backed flow table MUST record a per-flow disposition (allow, block, or redirect) when the
flow enforcer carries out a verdict, rather than acting on the socket itself, so the connection handler
that owns the flow applies the verdict without a race. A verdict for a flow that is not registered
(not live) MUST be an error, and the table MUST keep concurrent flows isolated.

#### Scenario: A BLOCK verdict sets the flow's disposition to block
- **WHEN** the flow enforcer carries out a BLOCK verdict for a registered flow_id
- **THEN** the flow table reports that flow's disposition as block

#### Scenario: A verdict for an unregistered flow is refused
- **WHEN** a verdict is carried out for a flow_id that was never registered
- **THEN** the flow table returns an error rather than recording a disposition
