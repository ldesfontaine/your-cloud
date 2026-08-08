package auxiliary

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// This file is everything that confines a managed service to its own machine:
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
	// There is one file and one table for the machine rather than one per confined
	// service, and the third door is the palier the previous one left that decision
	// to: a machine may now hold the delivered private profile beside any number of
	// user services, every one of them confined. They are named in this same table,
	// one block of three rules apiece, rather than given a table each — two tables
	// hooking the same chain would each have to be read to know what a machine
	// refuses, and a human reading a confinement should read one file.
	//
	// Which accounts belong in it is never remembered: it is established from the
	// sheets this machine holds, every time, so a table this Auxiliary reposes
	// converges on what the machine actually runs rather than on a record that
	// could be stale.
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

// confinedAccount is one account this machine refuses the traffic of, and the
// numeric identifier that machine gave it.
//
// The identifier lives here rather than in a placement because it is not a
// property of a service: it is allocated by the machine when the account is
// created, so it is read at the moment the table is posed and it is what makes
// the same rendered table mean the same thing on two different hosts.
type confinedAccount struct {
	account    string
	identifier int
}

// renderEgressRules builds the one confinement table of this machine, from the
// accounts it confines and the identifiers it gave them.
//
// Every account gets the same block of three rules, and the block is written out
// per account rather than folded into a set: a reviewer reads a firewall line by
// line, and a table where each account's three statements stand together — each
// with the reason it exists beside it — is one a human can check. A machine
// confining a single service therefore renders exactly the bytes `#102` proved,
// and a machine confining four renders four such blocks and nothing else.
//
// Rootless containers are why matching an account works at all. The engine of
// this product runs as the service's own account and its network stack is a
// userspace process of that same account, so every packet the service emits
// leaves this host from that identifier — which is exactly the sentence of the
// contract, "tout trafic sortant émis par le compte du service est refusé".
func renderEgressRules(confined []confinedAccount) []byte {
	rules := ""
	for _, subject := range confined {
		rules += fmt.Sprintf(`
		# The loopback of this machine, and it grants nothing outward. The sheet
		# of the account below publishes on the loopback alone, so this is the
		# line by which the port a human approved answers the machine it lives
		# on — the local verification of a deployment included. Nothing beyond
		# this host is reachable through it.
		%[1]s %[2]d oifname "lo" accept

		# The replies of connections somebody else opened towards this service,
		# and the whole of what may leave this machine on its behalf. The related
		# state is deliberately not accepted beside the established one: what the
		# contract names is replies, and an ICMP error carried on behalf of a
		# confined account is not one.
		%[1]s %[2]d ct state established accept

		# Everything else this account emits, in one line and with no exception
		# above it: no neighbour of the LAN, no registry, no name server, no mail
		# relay. A new connection this service opens is refused wherever it was
		# going, which is what makes "aucun voisin du LAN n'est joignable depuis
		# le service" a fact of this machine rather than a claim about a network.
		%[1]s %[2]d drop
`,
			egressAccountScope, subject.identifier,
		)
	}
	return []byte(fmt.Sprintf(`%[1]s
add table %[2]s %[3]s
delete table %[2]s %[3]s
table %[2]s %[3]s {
	chain output {
		type filter hook output priority filter; policy accept;
%[4]s	}
}
`,
		egressRulesPreamble(confined),
		egressTableFamily, egressTableName,
		rules,
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
//
// The accounts are named here in words because the rules below name them by the
// numbers this machine gave them: an administrator reading the file learns whose
// traffic it refuses without having to look an identifier up. The paragraph is
// written in the number the machine actually holds — a file that says "one
// service account" over four of them would be a comment that has stopped
// describing its own file, which is the first thing an operator stops trusting.
func egressRulesPreamble(confined []confinedAccount) string {
	head := `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
#
`
	if len(confined) == 1 {
		return head + `# This table only ever takes traffic away from one service account. Its chain
# carries an accept policy and drops what that account may not emit, so nothing
# here can grant this machine anything it did not already do. Every rule below is
# scoped to that account, and there is no exception.
#
# The confined account is ` + confined[0].account + `.`
	}
	named := make([]string, 0, len(confined))
	for _, subject := range confined {
		named = append(named, "#   "+subject.account)
	}
	return head + `# This table only ever takes traffic away from the service accounts named below.
# Its chain carries an accept policy and drops what those accounts may not emit,
# so nothing here can grant this machine anything it did not already do. Every
# rule below is scoped to one of them, and there is no exception.
#
# The confined accounts are:
` + strings.Join(named, "\n")
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

// egressBoundsState is what this machine was found holding of one confinement,
// read before anything is decided.
//
// The two presences are kept apart from the one verdict for the reason the
// passage's own state keeps them apart: an operation asks whether the confinement
// it is about to leave behind already holds, and the removal of the last confined
// service asks which of the two files are there to take away. A machine holding
// one of them is a drift for the first question and one removal for the second.
type egressBoundsState struct {
	rulesPresent bool
	unitPresent  bool
	// held is true only when this machine already holds exactly the confinement it
	// was asked about: both files carrying the bytes the named accounts and their
	// identifiers render, or — where nothing is to be confined — neither file at
	// all. It is the confinement's half of a deployment's idempotence: a flushed
	// table is a change the next approved plan reapplies, never a repair nobody
	// asked for.
	held bool
}

// readEgressBounds establishes that state against one desired confinement, and
// reads nothing else.
//
// The desired list is passed in rather than established here, because the two
// callers ask two different questions of one reading: a deployment asks whether
// the table already names everything it is about to name, and a removal asks
// whether the table already names everything but the account it is taking away.
// An empty list is the third question and it is answered here rather than by the
// caller — a machine that is to confine nothing holds this state exactly when it
// holds neither file.
func readEgressBounds(executor Executor, desired []confinedAccount) (egressBoundsState, error) {
	state := egressBoundsState{}
	currentRules, rulesPresent, err := executor.EgressRules(egressRulesPath)
	if err != nil {
		return state, fmt.Errorf("read the confinement this machine holds on its service accounts: %w", err)
	}
	currentUnit, unitPresent, err := executor.ReadUnitFile(egressRulesUnitPath)
	if err != nil {
		return state, fmt.Errorf("read the unit that poses the confinement at boot: %w", err)
	}
	state.rulesPresent = rulesPresent
	state.unitPresent = unitPresent
	if len(desired) == 0 {
		state.held = !rulesPresent && !unitPresent
		return state, nil
	}
	state.held = rulesPresent && bytes.Equal(currentRules, renderEgressRules(desired)) &&
		unitPresent && bytes.Equal(currentUnit, renderEgressRulesUnit())
	return state, nil
}

// noAccountIdentifier is what a caller carries when this machine holds no such
// account yet. It is not a valid identifier on any system: root is 0 and every
// allocated identifier is above it, so a table rendered from it could never be
// the one a real machine holds.
const noAccountIdentifier = -1

// confinedAccounts establishes which accounts this machine confines right now,
// from the sheets it holds rather than from a record this Auxiliary keeps.
//
// Two lists are walked and they are not the same kind of list. The delivered
// profiles are a closed constant of this package, so each of them is asked
// whether its sheet is there; the user services are not a list this product owns
// at all, so the machine is asked which of them it holds. Both answers are facts
// of the host, which is what makes a reposed table converge on what this machine
// actually runs.
//
// The result is ordered by account name so that two runs over one machine render
// one table, and a drift is a drift rather than a reordering.
func confinedAccounts(executor Executor) ([]confinedAccount, error) {
	confined := []confinedAccount{}
	for _, profile := range sortedProfiles(privateProfilePlacements) {
		where := privateProfilePlacements[profile]
		if !where.confined {
			continue
		}
		_, present, err := executor.ReadUnitFile(where.unitPath())
		if err != nil {
			return nil, fmt.Errorf("read the sheet of the %s profile: %w", profile, err)
		}
		if !present {
			continue
		}
		joined, err := joinedBy(executor, where)
		if err != nil {
			return nil, err
		}
		confined = append(confined, joined)
	}
	slugs, err := executor.ManagedUserServiceSlugs()
	if err != nil {
		return nil, fmt.Errorf("read the user services this machine holds: %w", err)
	}
	for _, slug := range slugs {
		joined, err := joinedBy(executor, userServicePlacementOfSlug(slug))
		if err != nil {
			return nil, err
		}
		confined = append(confined, joined)
	}
	sort.Slice(confined, func(first, second int) bool {
		return confined[first].account < confined[second].account
	})
	return confined, nil
}

// joinedBy names one placement's account beside the identifier this machine gave
// it. A sheet whose account has gone is a machine this operation does not run on,
// and it is named here rather than rendered as a table confining nobody.
func joinedBy(executor Executor, where placement) (confinedAccount, error) {
	identifier, err := executor.AccountIdentifier(where.account)
	if err != nil {
		return confinedAccount{}, fmt.Errorf("read the identifier of the %s account: %w", where.account, err)
	}
	return confinedAccount{account: where.account, identifier: identifier}, nil
}

// sortedProfiles names the entries of one closed placement list in one fixed
// order, so that every reading of it is the same reading on every run.
func sortedProfiles(placements map[string]placement) []string {
	profiles := make([]string, 0, len(placements))
	for profile := range placements {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	return profiles
}

// confinementJoinedBy is the confinement this machine will hold once the service
// being deployed is part of it, and confinementLeftBy is the one it will hold
// once that service is not.
//
// They are two functions over one reading because a deployment and a removal are
// the two directions of one fact: the table names the accounts of the managed
// services this machine runs, and an operation adds its own or takes it away. A
// deployment whose account does not exist yet carries noAccountIdentifier until
// it does, and it re-establishes the list once the account has been created —
// there is no identifier to render before an account exists, and inventing one
// would be a table confining a number this machine never allocated.
func confinementJoinedBy(executor Executor, where placement, identifier int) ([]confinedAccount, error) {
	confined, err := confinedAccounts(executor)
	if err != nil {
		return nil, err
	}
	if !where.confined || identifier == noAccountIdentifier {
		return confined, nil
	}
	for _, subject := range confined {
		if subject.account == where.account {
			return confined, nil
		}
	}
	confined = append(confined, confinedAccount{account: where.account, identifier: identifier})
	sort.Slice(confined, func(first, second int) bool {
		return confined[first].account < confined[second].account
	})
	return confined, nil
}

func confinementLeftBy(executor Executor, where placement) ([]confinedAccount, error) {
	confined, err := confinedAccounts(executor)
	if err != nil {
		return nil, err
	}
	remaining := make([]confinedAccount, 0, len(confined))
	for _, subject := range confined {
		if subject.account != where.account {
			remaining = append(remaining, subject)
		}
	}
	return remaining, nil
}

// settleEgressBounds brings this machine to one desired confinement, whichever
// of the two shapes that is.
//
// A machine that is to confine somebody poses the whole table; a machine that is
// to confine nobody has the table and its unit taken away. It is one function
// because it is one decision — "this is what this host refuses now" — and writing
// it twice in the two flows is how the two would come to disagree about the day
// the last confined service of a machine is removed.
func settleEgressBounds(executor Executor, state egressBoundsState, desired []confinedAccount) error {
	if len(desired) == 0 {
		return removeEgressBounds(executor, state)
	}
	return poseEgressBounds(executor, desired)
}

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
func poseEgressBounds(executor Executor, confined []confinedAccount) error {
	if err := executor.WriteEgressRules(egressRulesPath, renderEgressRules(confined)); err != nil {
		return fmt.Errorf("confine the service accounts to their own machine: %w", err)
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
			return fmt.Errorf("lift the confinement of the service accounts: %w", err)
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
