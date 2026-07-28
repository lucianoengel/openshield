## REMOVED Requirements

### Requirement: Post-decision enforcement contains, it does not prevent

**Reason**: The requirement states that "inline blocking within the permission window is not provided"
and "stays deferred because the pipeline cannot complete in the permission window". Neither is true now:
HIPS-3 answers an exec-permission event with DENY, NIPS-1 drops a flow at L4, the gateway refuses an
upload before forwarding it, the print filter refuses a job before it prints, and the USB enforcer
deauthorizes a device. The requirement was written when file access was the only channel, and its
reasoning — that a file must be READ to be classified, so the read cannot be blocked on the
classification — remains correct for that channel and only that one.

**Migration**: Replaced by "Prevention is claimed only where the product prevents", which draws the line
per domain rather than denying prevention outright. The anti-overclaim rule (D16) is preserved and
strengthened: each claim now names the mechanism that implements it, and the file-access claim is
unchanged because the mechanism is unchanged.

## ADDED Requirements

### Requirement: Prevention is claimed only where the product prevents

Documentation and every operator-facing surface SHALL describe enforcement per domain, and SHALL NOT
generalize either way — neither claiming prevention the product does not perform, nor denying prevention
it does. A claim of prevention MUST name the mechanism that carries it out.

**Prevented inline**, before the operation completes: an execution (an exec-permission event answered
DENY), a network flow (dropped at L4, or refused by the gateway before it is forwarded), a print job
(refused before it reaches the printer), a clipboard paste where the display server permits mediation,
and a USB device (deauthorized).

**Contained after the fact**, never prevented: FILE ACCESS. The file was already read — that is how it
was classified — so quarantine, encrypt-local and revocation act on a read that already happened. This
is the original limit and it is unchanged, because the mechanism is unchanged: nothing in the shipped
product answers a file-open permission event.

**Defeatable by root** in every case (D16). None of the above is a claim of prevention against an
administrator of the host.

#### Scenario: A file-access surface claims containment, not prevention

- **WHEN** enforcement of a filesystem decision is described
- **THEN** it is described as post-decision containment, defeatable by root, and does not claim the
  offending read was prevented

#### Scenario: An inline-prevention surface names its mechanism

- **WHEN** a surface states that an execution, flow, print job, paste or device was prevented
- **THEN** the mechanism that prevented it is named, and the claim is not generalized to file access

#### Scenario: No surface claims prevention against root

- **WHEN** any enforcement is described
- **THEN** it is qualified as defeatable by an administrator of the host
