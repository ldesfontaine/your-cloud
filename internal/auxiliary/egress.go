package auxiliary

import (
	"bytes"
	"fmt"
	"strings"
)

// This file is everything that confines a private service to its own machine:
// the single nftables table a deployment poses, and the oneshot unit that puts
// it back after a reboot.
//
// It is the sibling of the passage's own bounding table, written in the same
// conventions and for the opposite reason. The passage's table says what may
// cross one interface; this one says what one *account* may emit, on every
// interface at once, and the answer is nothing — no neighbour of the LAN, no
// registry, no mail relay, nothing. The service of this profile needs no outward
// connection at all, so what it is allowed is the empty set plus two statements
// that are not permissions: its own loopback, which is how the machine reaches
// the port the sheet publishes, and the replies of connections somebody else
// opened.
//
// No value of a plan reaches this file. The one value that does is a fact about
// the machine — the numeric identifier of the service's own account — read at the
// moment the table is posed, written with %d from an integer, and never carried
// in a document: an account identifier is allocated by the machine that creates
// the account, so a plan naming one would be a plan describing a machine it has
// never seen.
//
// One property runs through every rule and is stated once, here: **this table can
// only take traffic away from one account, and can never grant anything.** Its
// single base chain carries an accept policy and drops exactly what that account
// emits without matching an approved line, so a machine holding this table does
// everything it did before minus what the confined service is not allowed to do.
// Every rule is scoped by `meta skuid` to that one account, without exception.

const (
	// egressTableFamily and egressTableName are the one table a private
	// deployment poses, and the only table any effect of this file ever names. A
	// removal deletes this table by name and touches no other, which is what lets
	// a machine carry a firewall of its own — and the passage's own table — beside
	// a confined service.
	egressTableFamily = "inet"
	egressTableName   = "your-cloud-egress"

	// egressRoot and egressRulesPath are where the posed table is kept, beside the
	// two other trees this Auxiliary owns under /etc/your-cloud and under the same
	// rule: root-owned files this package writes and nothing else may rewrite.
	//
	// There is one file and one table for the machine rather than one per profile,
	// because there is one confined profile. A second confined profile would have
	// to be named in this same table beside the first — one table, one file, both
	// accounts — rather than given a table of its own, since two tables hooking
	// the same chain would each have to be read to know what a machine refuses.
	// That decision belongs to the palier that adds such a profile; until then
	// this file states it rather than leaving it to be discovered.
	egressRoot      = "/etc/your-cloud/egress"
	egressRulesPath = egressRoot + "/rules.nft"

	// egressRulesUnitName and egressRulesUnitPath are the oneshot unit that poses
	// the table again at boot.
	//
	// It exists because a table loaded with `nft -f` lives in the kernel and not
	// on disk: without it, the first reboot of a machine would bring the confined
	// service back with its confinement gone, and nothing would say so. The
	// passage learned exactly that lesson on a real machine, and the answer here
	// is the one it settled on — one unit, ordered before anything that could
	// start the service, applying the very file the deployment wrote.
	egressRulesUnitName = "your-cloud-egress-rules.service"
	egressRulesUnitPath = "/etc/systemd/system/" + egressRulesUnitName

	// egressAccountScope is how every rule of this table says which account it is
	// about. It is held as a constant because the property "no rule without an
	// account scope" is checked against it rather than against a spelling repeated
	// in a test.
	egressAccountScope = "meta skuid"
)

// renderEgressRules builds the one confinement table of one placement, from that
// placement's constants and the numeric identifier its account was given on this
// machine.
//
// The identifier is a parameter rather than a field of the placement because it
// is not a property of the profile: it is allocated by the machine when the
// account is created, so it is read at the moment the table is posed and it is
// what makes the same rendered table mean the same thing on two different hosts.
//
// Rootless containers are why matching the account works at all. The engine of
// this product runs as the service's own account and its network stack is a
// userspace process of that same account, so every packet the service emits
// leaves this host from that identifier — which is exactly the sentence of the
// contract, "tout trafic sortant émis par le compte du service est refusé".
func renderEgressRules(where placement, accountIdentifier int) []byte {
	return []byte(fmt.Sprintf(`%[1]s
add table %[2]s %[3]s
delete table %[2]s %[3]s
table %[2]s %[3]s {
	chain output {
		type filter hook output priority filter; policy accept;

		# The loopback of this machine, and it grants nothing outward. The sheet
		# of the account below publishes on the loopback alone, so this is the
		# line by which the port a human approved answers the machine it lives
		# on — the local verification of a deployment included. Nothing beyond
		# this host is reachable through it.
		%[5]s %[6]d oifname "lo" accept

		# The replies of connections somebody else opened towards this service,
		# and the whole of what may leave this machine on its behalf. The related
		# state is deliberately not accepted beside the established one: what the
		# contract names is replies, and an ICMP error carried on behalf of a
		# confined account is not one.
		%[5]s %[6]d ct state established accept

		# Everything else this account emits, in one line and with no exception
		# above it: no neighbour of the LAN, no registry, no name server, no mail
		# relay. A new connection this service opens is refused wherever it was
		# going, which is what makes "aucun voisin du LAN n'est joignable depuis
		# le service" a fact of this machine rather than a claim about a network.
		%[5]s %[6]d drop
	}
}
`,
		egressRulesPreamble(where.account),
		egressTableFamily, egressTableName,
		where.account,
		egressAccountScope, accountIdentifier,
	))
}

// egressRulesPreamble is the head the table opens with: who wrote the file, and
// the idiom that makes loading it twice mean the same as loading it once.
//
// The three statements are one transaction, exactly as the passage's are. Adding
// the table does nothing when it is already there and creates an empty one when
// it is not, which is what makes the deletion that follows always succeed; the
// definition then writes the whole table from scratch. A machine that drifted and
// a machine that never held this table reach the same state, and no rule is ever
// appended twice.
// The account is named here in words, once, because the rules below name it by
// the number this machine gave it: an administrator reading the file learns whose
// traffic it refuses without having to look an identifier up.
func egressRulesPreamble(account string) string {
	return `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
#
# This table only ever takes traffic away from one service account. Its chain
# carries an accept policy and drops what that account may not emit, so nothing
# here can grant this machine anything it did not already do. Every rule below is
# scoped to that account, and there is no exception.
#
# The confined account is ` + account + `.`
}

// renderEgressRulesUnit builds the oneshot unit that poses the table at boot.
//
// It takes no argument at all, because everything it names is a constant: the
// program, the file, and the moment. Three decisions are carried here:
//
//   - it runs before `network-pre.target`, which is the ordering a firewall unit
//     is given on this system: the table is in the kernel before any network
//     exists and therefore long before logind starts the lingering user manager
//     that starts the confined service. A confinement that came back after the
//     thing it confines would be a window nobody could see;
//   - it applies the very file the deployment wrote, by its own path, so a
//     machine coming back from a reboot passes through the same state by the same
//     command as a machine being deployed;
//   - it stays a declared effect of the deployment plan rather than a step of a
//     bootstrap, exactly as the passage's own bounds are: the human who approves
//     a private service approves this machine putting its confinement back at
//     every boot, and removing the service takes the unit away with it.
func renderEgressRulesUnit() []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=Your Cloud private service egress confinement
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target
ConditionPathExists=%s

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=%s --file %s

[Install]
WantedBy=sysinit.target
`,
		egressRulesPath,
		nftProgram, egressRulesPath,
	))
}

// egressBoundsState is what this machine was found holding of the confinement
// one deployment describes, read before anything is decided.
//
// The two presences are kept apart from the one verdict for the reason the
// passage's own state keeps them apart: a deployment asks whether the approved
// confinement already holds, and a removal asks which of the two files are there
// to take away. A machine holding one of them is a drift for the first question
// and one removal for the second.
type egressBoundsState struct {
	rulesPresent bool
	unitPresent  bool
	// held is true only when both files are there and carry exactly the bytes
	// this machine's own account identifier renders. It is the confinement's half
	// of a deployment's idempotence: a flushed table is a change the next approved
	// plan reapplies, never a repair nobody asked for.
	held bool
}

// present reports whether this machine holds any of the confinement at all,
// which is what a removal asks before deciding there is nothing to take away.
func (state egressBoundsState) present() bool {
	return state.rulesPresent || state.unitPresent
}

// readEgressBounds establishes that state, and reads nothing else.
//
// The account identifier is passed in rather than read here, because the caller
// is the one that knows whether the account exists at all: a machine that has
// never held this profile has no such account, so there is no identifier to read
// and the approved bytes cannot be rendered — which is not a drift to repair but
// a deployment that has not happened yet. Such a caller passes noAccountIdentifier
// and gets the two presences with held false, which is exactly the truth.
func readEgressBounds(executor Executor, where placement, accountIdentifier int) (egressBoundsState, error) {
	state := egressBoundsState{}
	currentRules, rulesPresent, err := executor.EgressRules(egressRulesPath)
	if err != nil {
		return state, fmt.Errorf("read the confinement this machine holds on the service account: %w", err)
	}
	currentUnit, unitPresent, err := executor.ReadUnitFile(egressRulesUnitPath)
	if err != nil {
		return state, fmt.Errorf("read the unit that poses the confinement at boot: %w", err)
	}
	state.rulesPresent = rulesPresent
	state.unitPresent = unitPresent
	if accountIdentifier == noAccountIdentifier {
		return state, nil
	}
	state.held = rulesPresent && bytes.Equal(currentRules, renderEgressRules(where, accountIdentifier)) &&
		unitPresent && bytes.Equal(currentUnit, renderEgressRulesUnit())
	return state, nil
}

// noAccountIdentifier is what a caller passes when this machine holds no such
// account yet. It is not a valid identifier on any system: root is 0 and every
// allocated identifier is above it.
const noAccountIdentifier = -1

// poseEgressBounds writes and applies the confinement, in the order this file
// fixes once.
//
// The order is an argument and not a habit:
//
//  1. the table is applied first, which is the moment this account stops being
//     able to reach anything. It is applied before the service is started and
//     after the image was fetched, because fetching runs as that very account and
//     the table refuses exactly what fetching needs;
//  2. the unit is written and enabled second, because what it does is put the
//     file above back at the next boot, and there is nothing to put back until it
//     exists.
func poseEgressBounds(executor Executor, where placement, accountIdentifier int) error {
	if err := executor.WriteEgressRules(egressRulesPath, renderEgressRules(where, accountIdentifier)); err != nil {
		return fmt.Errorf("confine the service account to its own machine: %w", err)
	}
	if err := executor.WriteUnitFile(egressRulesUnitPath, renderEgressRulesUnit()); err != nil {
		return fmt.Errorf("write the unit that poses the confinement at boot: %w", err)
	}
	if err := executor.EnableEgressRulesAtBoot(); err != nil {
		return fmt.Errorf("make this machine pose the confinement again after a reboot: %w", err)
	}
	return nil
}

// removeEgressBounds takes them away, in the exact inverse order, and takes away
// only what this machine was found holding.
//
// It is called after the service has been stopped and never before it, which is
// the mirror of the rule above: the confinement is posed before anything of the
// service runs and lifted once nothing of it runs any more, so there is no
// instant of either operation in which this machine holds a running service that
// nothing confines. Lifting it first would produce exactly that instant.
func removeEgressBounds(executor Executor, state egressBoundsState) error {
	if state.unitPresent {
		if err := executor.DisableEgressRulesAtBoot(); err != nil {
			return fmt.Errorf("stop posing the confinement after a reboot: %w", err)
		}
		if err := executor.RemoveUnitFile(egressRulesUnitPath); err != nil {
			return fmt.Errorf("remove the unit that posed the confinement at boot: %w", err)
		}
	}
	if state.rulesPresent {
		if err := executor.RemoveEgressRules(egressRulesPath); err != nil {
			return fmt.Errorf("lift the confinement of the service account: %w", err)
		}
	}
	return nil
}

// egressRuleLines is every rule the rendered table carries, with the chain
// declarations, the comments and the braces left out.
//
// It exists so that the property this file opens with — no rule without an
// account scope — is read from the bytes that are actually written rather than
// from a list somebody kept up to date beside them.
func egressRuleLines(rules []byte) []string {
	lines := []string{}
	for _, line := range strings.Split(string(rules), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "",
			strings.HasPrefix(trimmed, "#"),
			strings.HasPrefix(trimmed, "add table "),
			strings.HasPrefix(trimmed, "delete table "),
			strings.HasPrefix(trimmed, "table "),
			strings.HasPrefix(trimmed, "chain "),
			strings.HasPrefix(trimmed, "type "),
			trimmed == "}":
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}
