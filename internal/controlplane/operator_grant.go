package controlplane

import (
	"fmt"
	"strings"
)

// CONSOLE-1: THE ADMIN TIER FUSED TWO AUTHORITIES THAT BELONG TO DIFFERENT PEOPLE.
//
// `admin` meant "can change configuration" AND "can read everything the platform holds about a named
// human" — release a legal hold so evidence about that person becomes purgeable, compile the DSAR
// dossier, and read the record of who looked at what. Those are not one job. Tuning detection is an
// operations responsibility; answering for what is held about a named individual is a data-protection
// one, and every regime this project claims to help with expects the second person to be independent of
// the first (GDPR Art. 38(3) states it outright).
//
// The consequence is concrete rather than theoretical: today the operator who can switch a detection
// off is the same operator who can pull the subject dossier, and nobody with standing to object can see
// either act. THE ADMIN ADMINISTERS THE SYSTEM; THE PRIVACY OFFICER OVERSEES THE ADMIN. That only means
// anything if they can be different people.
//
// # WHY THIS IS NOT A FOURTH RANK
//
// The tiers are a linear order — analyst < responder < admin — because each does strictly more than the
// one below, and `roleRank` encodes exactly that. A privacy officer does not do more than an admin, or
// less: they do something ELSE. Ranked above admin they would inherit configuration; ranked below, an
// admin would inherit the dossier. Neither is the separation being asked for.
//
// So the privacy authority is a SECOND AXIS, and a grant is a point on both — at most one tier, plus
// the privacy flag or not. That is why this is a struct and not a bigger `roleRank` switch.

// RolePrivacyOfficer is the data-subject authority: DSAR export, legal-hold release, and the record of
// who viewed an investigation.
//
// IT IS NOT A TIER AND NEVER SATISFIES ONE. `roleRank` leaves it at 0 on purpose, so a privacy officer
// reaches exactly the routes that name it and nothing else — no alert queue, no incident lifecycle, no
// configuration. Granting the oversight role read of the whole console would rebuild, from the other
// side, the fusion this exists to break.
//
// It is equally deliberate that `certRole` does not recognise it: the privacy authority cannot be
// asserted by a certificate OU, so a CA cannot mint one and the legacy fallback can never grant it.
const RolePrivacyOfficer = "privacy-officer"

// operatorGrant is what one operator holds — at most one operational tier, plus the orthogonal privacy
// authority.
//
// Stored as two columns rather than one string, because they are two independent facts. A single column
// holding "admin,privacy-officer" would need parsing on every authorization lookup, and a column that
// must be parsed before it can be trusted is a column that will eventually be compared without parsing.
type operatorGrant struct {
	// Tier is "", analyst, responder, admin, or the legacy `operator` (which ranks as admin). Read
	// straight from the database without parsing, so a value written before this split still ranks.
	Tier string
	// Privacy is the data-subject authority. Independent of Tier in both directions.
	Privacy bool
}

// empty reports a grant that authorizes nothing. It is the state of a recorded-but-ungranted identity
// (SCIM provisioning writes one) and of any row whose tier is unrecognised — deny by default.
func (g operatorGrant) empty() bool { return roleRank(g.Tier) == 0 && !g.Privacy }

// satisfies reports whether this grant meets a route's requirement.
//
// The two axes are checked SEPARATELY and never fall through to each other. That is the whole control:
// an admin asking for a privacy route is refused by the first branch, and a privacy officer asking for
// a tier route is refused by the second because roleRank("privacy-officer") — and roleRank("") for a
// privacy-only grant — is 0.
func (g operatorGrant) satisfies(require string) bool {
	if require == RolePrivacyOfficer {
		return g.Privacy
	}
	return roleRank(g.Tier) >= roleRank(require)
}

// String is the canonical spelling of a grant, and it is exactly what `operator-role set` accepts. An
// operator reading `operator-role list` must be able to paste what they see back into the command that
// produces it; anything else invites a re-grant that means something slightly different.
func (g operatorGrant) String() string {
	var parts []string
	if g.Tier != "" {
		parts = append(parts, g.Tier)
	}
	if g.Privacy {
		parts = append(parts, RolePrivacyOfficer)
	}
	return strings.Join(parts, ",")
}

// parseGrant reads a grant specification: `analyst`, `responder`, `admin`, `privacy-officer`, or a tier
// and `privacy-officer` separated by a comma.
//
// TWO TIERS IS AN ERROR RATHER THAN THE HIGHER ONE. Silently taking the maximum of a contradictory
// grant is how a typo becomes an escalation, and the caller here is always a human at a CLI who can
// simply be told.
//
// `operator` is not accepted, unchanged from the closed set it replaces: the legacy full-access role is
// honoured where it already exists in the table and cannot be newly granted. After this split it would
// mean "admin and privacy officer at once", which is precisely the fusion being removed.
func parseGrant(spec string) (operatorGrant, error) {
	var g operatorGrant
	for _, part := range strings.Split(spec, ",") {
		switch part = strings.TrimSpace(part); part {
		case RoleAnalyst, RoleResponder, RoleAdmin:
			if g.Tier != "" && g.Tier != part {
				return operatorGrant{}, fmt.Errorf("controlplane: %q grants two tiers (%s and %s) — an "+
					"operator holds at most one", spec, g.Tier, part)
			}
			g.Tier = part
		case RolePrivacyOfficer:
			g.Privacy = true
		default:
			return operatorGrant{}, fmt.Errorf("controlplane: %q is not an operator grant (want analyst, "+
				"responder, admin, privacy-officer, or a tier and privacy-officer separated by a comma)",
				part)
		}
	}
	if g.empty() {
		return operatorGrant{}, fmt.Errorf("controlplane: %q grants nothing", spec)
	}
	return g, nil
}
