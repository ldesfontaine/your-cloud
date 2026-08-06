package auxiliary

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// This file is everything that bounds the private passage to one service on a
// machine: the single nftables table a junction poses, the redirection the
// initiator needs because a managed service only ever listens on the loopback,
// the interface-scoped host relaxation that redirection requires, and the
// oneshot unit that puts the two back after a reboot.
//
// Exactly one value of a plan reaches this file: the approved service port. It
// arrives as an integer the plan validation has already bounded to
// 1024..65535, it has already been held against a managed service this machine
// actually publishes, and it is written with %d from that integer — so no text
// of a plan is ever interpolated into a rule. Everything else below is a
// constant: the table's name, the interface, the two addresses of the tunnel,
// the listening port of the contract and the loopback address.
//
// One property runs through every rule and is stated once, here: **this table
// can only take traffic away from the passage, and can never grant anything.**
// Its base chains carry an accept policy and drop exactly what arrives on or
// leaves by `yc-link0` without matching an approved line, so a machine holding
// this table does everything it did before minus what the passage is not
// allowed to carry. Two consequences follow and both are named where they
// happen: every rule is scoped by `iifname` or `oifname` to the passage's own
// interface, with a single deliberate exception; and that exception is a
// statement rather than a permission, because an accept in a table that never
// drops anything else opens nothing.

const (
	// linkTableFamily and linkTableName are the one table this passage poses,
	// and the only table any effect of this file ever names. A removal deletes
	// this table by name and touches no other, which is what lets a machine
	// carry a firewall of its own beside a passage.
	linkTableFamily = "inet"
	linkTableName   = "your-cloud-link"

	// linkRulesPath is where the rules a junction posed are kept, beside the key
	// and under the same root-owned tree: they are the two things a passage owns
	// on this machine that nothing but this Auxiliary may write.
	linkRulesPath = linkRoot + "/rules.nft"

	// linkLoopbackPolicyPath is the one host relaxation a passage declares, and
	// it is written where the entrypoint's own relaxation is written, for the
	// same reason: an administrator reading /etc/sysctl.d learns which plan owns
	// which line, and the file carries the name of the thing that owns it.
	linkLoopbackPolicyPath = "/etc/sysctl.d/your-cloud-link.conf"

	// linkRouteLocalnetKey is the exact setting that relaxation carries. It is
	// the per-interface one and never `all`: what is allowed is routing towards
	// the loopback for packets arriving on the passage's interface, and for
	// packets arriving on no other.
	linkRouteLocalnetKey = "net.ipv4.conf." + LinkInterfaceName + ".route_localnet"

	// linkRulesUnitName and linkRulesUnitPath are the oneshot unit that puts the
	// bounds back at boot.
	//
	// It exists because neither half of what a junction applies survives a
	// reboot on its own: a table loaded with `nft -f` lives in the kernel and
	// not on disk, and an interface-scoped sysctl written under /etc/sysctl.d is
	// read by systemd-sysctl long before any network manager has created the
	// interface it names, so at boot that line applies to nothing. One unit
	// ordered after the network manager applies both, in the order the junction
	// applied them, from the very files the junction wrote.
	linkRulesUnitName = "your-cloud-link-rules.service"
	linkRulesUnitPath = "/etc/systemd/system/" + linkRulesUnitName

	// sysctlProgram and nftProgram are the two programs a passage asks a machine
	// for, named by their absolute paths because a systemd unit takes nothing
	// else and because the effects of this package run fixed argument vectors. A
	// machine missing either of them fails by name at the moment a junction is
	// applied, rather than silently at the next boot.
	sysctlProgram = "/usr/sbin/sysctl"
	nftProgram    = "/usr/sbin/nft"

	// linkRulesInterfaceScopes are the two ways a rule of this table says which
	// interface it is about. Nothing here is a value: they are held as constants
	// because the property "no rule without an interface scope" is checked
	// against them rather than against a spelling repeated in a test.
	linkInputScope  = `iifname "` + LinkInterfaceName + `"`
	linkOutputScope = `oifname "` + LinkInterfaceName + `"`
)

// renderLinkRules builds the one bounding table of a role, from that role's
// constants and the single approved port.
//
// There is one renderer per role rather than one renderer with branches,
// because the two tables state opposite things: the listener reaches out and
// never answers on the passage, the initiator answers and never reaches out.
// Written as one function with conditionals, neither table could be read whole.
func renderLinkRules(where linkPlacement, servicePort int) []byte {
	if where.listens {
		return renderListenerRules(servicePort)
	}
	return renderInitiatorRules(servicePort)
}

// renderListenerRules is the table the public machine holds.
//
// What it allows through the passage is one direction and one couple: TCP
// leaving towards the initiator's own tunnel address, on the approved port. SSH,
// every other port, every other protocol and every other destination fall to the
// drops, and nothing is relayed.
func renderListenerRules(servicePort int) []byte {
	return []byte(fmt.Sprintf(`%[1]s
add table %[2]s %[3]s
delete table %[2]s %[3]s
table %[2]s %[3]s {
	chain input {
		type filter hook input priority filter; policy accept;

		# The one line of this table without an interface scope, and it grants
		# nothing at all: a chain whose policy is accept and which drops only
		# what arrives on %[4]s cannot open a port this machine was not
		# already answering on. What this line does is name the single public
		# port the passage adds to this host — the UDP the tunnel is carried
		# by — inside the machine's own ruleset, so that it is read there
		# beside the rest of the passage instead of being inferred from a
		# socket. This product owns no host firewall and this table is not one.
		udp dport %[5]d accept

		# What the passage may bring in, and the whole of it: the replies of the
		# connections this machine itself opened towards the approved service.
		# The related state is deliberately not accepted beside the established
		# one: the tunnel has a fixed MTU both ends know, so nothing here
		# depends on an ICMP error being carried, and the contract says replies.
		%[6]s ct state established accept
		%[6]s drop
	}

	chain output {
		type filter hook output priority filter; policy accept;

		# The whole of what may leave through the passage: TCP towards the one
		# address of the peer, on the one port a human approved. The
		# destination is the role's constant and never a plan value, so a
		# junction naming another destination cannot be written — there is no
		# field for one.
		%[7]s ip daddr %[8]s tcp dport %[9]d accept
		%[7]s drop
	}

	chain forward {
		type filter hook forward priority filter; policy accept;

		# Nothing is relayed, in either direction: neither machine becomes a way
		# towards the network behind the other.
		%[6]s drop
		%[7]s drop
	}
}
`,
		linkRulesPreamble(),
		linkTableFamily, linkTableName,
		LinkInterfaceName,
		linkListenPort,
		linkInputScope,
		linkOutputScope,
		linkInitiatorAddress, servicePort,
	))
}

// renderInitiatorRules is the table the machine of the LAN holds, and it carries
// the one thing no other table of this product carries: a redirection.
//
// The reason is a constant of the service sheets rather than a decision of this
// passage: a managed service publishes on 127.0.0.1 and on nothing else, so
// traffic arriving on the tunnel addressed to the initiator's own tunnel address
// reaches a port nothing is listening on. The redirection sends exactly the
// approved port to exactly that loopback port, and the filter chain below
// refuses everything else independently of it — the two are separate layers and
// neither covers for the other.
//
// There is no line in this table towards the LAN, and there could not be one:
// nothing is forwarded, so the machine of the LAN relays nothing of the network
// it sits on.
func renderInitiatorRules(servicePort int) []byte {
	return []byte(fmt.Sprintf(`%[1]s
add table %[2]s %[3]s
delete table %[2]s %[3]s
table %[2]s %[3]s {
	chain prerouting {
		type nat hook prerouting priority dstnat;

		# The approved port of the tunnel, sent to the same port of this
		# machine's loopback, for packets arriving on %[4]s from the one
		# address the peer may be. Nothing else of the tunnel is redirected, so
		# every other port keeps the destination it was sent to — where nothing
		# answers — and is dropped by the chain below on its own merits.
		%[5]s ip saddr %[6]s tcp dport %[7]d dnat ip to %[8]s:%[7]d
	}

	chain input {
		type filter hook input priority filter; policy accept;

		# The one thing the passage may bring in: TCP from the listener's own
		# address towards the approved port. The destination address is
		# deliberately not matched, because the redirection above has already
		# rewritten it to the loopback by the time this chain runs — what is
		# held here is where the packet came from and where it was going.
		#
		# No state line stands beside it: every packet of an accepted flow
		# arrives with that same source and that same port, so a state rule
		# here would match nothing this line does not already match, and a
		# control that grants nothing still reads as a control that was needed.
		%[5]s ip saddr %[6]s tcp dport %[7]d accept
		%[5]s drop
	}

	chain output {
		type filter hook output priority filter; policy accept;

		# Only the replies of the connections the listener opened leave by the
		# passage. This machine never opens anything on %[4]s: what it opens
		# is the tunnel itself, which is UDP on another interface entirely and
		# is not this table's business.
		%[9]s ct state established accept
		%[9]s drop
	}

	chain forward {
		type filter hook forward priority filter; policy accept;

		# Nothing is relayed, in either direction. This is the line that keeps
		# the passage from becoming a way into the LAN this machine sits on.
		%[5]s drop
		%[9]s drop
	}
}
`,
		linkRulesPreamble(),
		linkTableFamily, linkTableName,
		LinkInterfaceName,
		linkInputScope,
		linkListenerAddress, servicePort,
		loopbackAddress,
		linkOutputScope,
	))
}

// linkRulesPreamble is the head both tables open with: who wrote the file, and
// the idiom that makes loading it twice mean the same as loading it once.
//
// The three statements are one transaction. Adding the table does nothing when
// it is already there and creates an empty one when it is not, which is what
// makes the deletion that follows always succeed; the definition then writes the
// whole table from scratch. A machine that drifted and a machine that never held
// this table reach the same state, and no rule is ever appended twice.
func linkRulesPreamble() string {
	return `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
#
# This table only ever takes traffic away from ` + LinkInterfaceName + `. Its chains carry an
# accept policy and drop what the passage may not carry, so nothing here can
# grant this machine anything it did not already do. Every rule below is scoped
# to that interface, except one line that is named where it is written.`
}

// renderLinkLoopbackPolicy builds the one host relaxation a passage declares.
//
// Routing a packet towards 127.0.0.1 from a real interface is refused by the
// kernel unless that interface is told otherwise, so without this line the
// redirection above would send the approved traffic to a destination the routing
// layer discards. The setting is scoped to the passage's own interface and never
// to `all`: the machine keeps refusing loopback destinations from every other
// interface it holds, including the one facing its LAN.
func renderLinkLoopbackPolicy() []byte {
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary as a declared effect of one approved
# junction plan. It is removed when that junction is removed, and by nothing
# else. Do not edit: this machine compares this file byte for byte against the
# plan it is given.
#
# It is read again at boot by %s, because the
# interface it names does not exist yet when this machine reads /etc/sysctl.d.
%s=1
`, linkRulesUnitName, linkRouteLocalnetKey))
}

// renderLinkRulesUnit builds the oneshot unit that puts the bounds back at boot.
//
// It takes the role, because the unit may only name what its own machine
// holds: the host relaxation exists on the initiator alone, and a listener
// unit that loaded a policy file no junction ever wrote would fail its first
// command and never reach the table — the first machine proof came back from
// a reboot with a tunnel established and no bounds at all, exactly that way.
// Three more decisions are carried here:
//
//   - it is ordered after the network manager, because both things it applies
//     name an interface that manager creates. Applied earlier, the sysctl would
//     silently apply to nothing and the table would bound an interface that does
//     not exist;
//   - the initiator applies the sysctl before the table, in the order the
//     junction applied them, so a machine coming back from a reboot passes
//     through the same states in the same sequence as a machine being joined;
//   - it stays a declared effect of the junction plan rather than a step of a
//     bootstrap, exactly as the entrypoint's host policy is: the human who
//     approves a junction approves this machine putting these files back at
//     every boot, and undoing the junction takes the unit away with them.
func renderLinkRulesUnit(where linkPlacement) []byte {
	policy := ""
	if where.goesOut {
		policy = fmt.Sprintf("ExecStart=%s --quiet --load %s\n", sysctlProgram, linkLoopbackPolicyPath)
	}
	return []byte(fmt.Sprintf(`# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=Your Cloud private passage bounds
After=systemd-networkd.service
Wants=systemd-networkd.service
ConditionPathExists=%s

[Service]
Type=oneshot
RemainAfterExit=yes
%sExecStart=%s --file %s

[Install]
WantedBy=multi-user.target
`,
		linkRulesPath,
		policy,
		nftProgram, linkRulesPath,
	))
}

// requireBoundedService holds the contract's own sentence — the service port
// "doit nommer le port loopback d'un service géré présent" — against this
// machine, before anything is written.
//
// It is the passage's spelling of what requireManagedBackend does for a route,
// over the same reading of the same sheets: what a passage may be bounded to is
// a managed service of this machine, described by a plan a human approved, and
// never whatever process got to the port first.
//
// The listener has nothing to check and the absence is deliberate rather than an
// omission: the service being reached lives on the machine at the other end of
// the tunnel, so a listener asked to prove a local service would refuse every
// correct junction of the reference scenario. What bounds the listener is that
// the port it may reach is the one the human approved on both plans, which the
// approval itself already holds.
func requireBoundedService(executor Executor, where linkPlacement, servicePort int) error {
	if !where.goesOut {
		return nil
	}
	published, err := publishesLoopbackPort(executor, servicePort)
	if err != nil {
		return err
	}
	if published {
		return nil
	}
	return fmt.Errorf(
		"no managed service of this machine publishes %s:%d: a passage bounded to a port nothing manages would be a passage towards whatever got to that port first, so it is refused before any effect",
		loopbackAddress, servicePort,
	)
}

// linkBoundsState is what this machine was found holding of the bounds one
// junction describes, read before anything is decided.
//
// The three presences are kept apart from the one verdict on purpose: a
// junction asks whether the approved bounds already hold, and a departure asks
// which of the three files are there to take away. A machine holding two of them
// is a drift for the first question and three separate removals for the second.
type linkBoundsState struct {
	rulesPresent  bool
	unitPresent   bool
	policyPresent bool
	// held is true only when every file this role owns is there and carries
	// exactly the bytes the approved plan describes. It is the bounds' half of
	// the junction's idempotence: an edited table is a change reapplied by the
	// next approved plan, never a repair nobody asked for.
	held bool
}

// readLinkBounds establishes that state, and reads nothing else.
//
// The host relaxation is read on the initiator alone, because it is written on
// the initiator alone: asking a listener for a file no plan of its role ever
// wrote would turn "this machine never had one" into a drift to repair.
func readLinkBounds(executor Executor, where linkPlacement, servicePort int) (linkBoundsState, error) {
	state := linkBoundsState{}
	currentRules, rulesPresent, err := executor.LinkRules()
	if err != nil {
		return state, fmt.Errorf("read the bounds this machine holds on the passage: %w", err)
	}
	currentUnit, unitPresent, err := executor.ReadUnitFile(linkRulesUnitPath)
	if err != nil {
		return state, fmt.Errorf("read the unit that puts the bounds back at boot: %w", err)
	}
	state.rulesPresent = rulesPresent
	state.unitPresent = unitPresent
	state.held = rulesPresent && bytes.Equal(currentRules, renderLinkRules(where, servicePort)) &&
		unitPresent && bytes.Equal(currentUnit, renderLinkRulesUnit(where))

	if !where.goesOut {
		return state, nil
	}
	currentPolicy, policyPresent, err := executor.LinkLoopbackPolicy()
	if err != nil {
		return state, fmt.Errorf("read the host relaxation the passage declares: %w", err)
	}
	state.policyPresent = policyPresent
	state.held = state.held && policyPresent && bytes.Equal(currentPolicy, renderLinkLoopbackPolicy())
	return state, nil
}

// present reports whether this machine holds any of the bounds at all, which is
// what a departure asks before deciding that there is nothing to undo.
func (state linkBoundsState) present() bool {
	return state.rulesPresent || state.unitPresent || state.policyPresent
}

// linkBoundsLeftBehind answers the same question without a role, for the one
// caller that deliberately has none.
//
// A withdrawal reaches the same state from either side and therefore never reads
// the role back, so it cannot ask readLinkBounds — which needs a role to know
// whether a host relaxation is one of the files to expect. What it needs is
// weaker anyway: not whether the approved bounds hold, but whether anything of
// them is still there to be left behind.
func linkBoundsLeftBehind(executor Executor) (bool, error) {
	if _, present, err := executor.LinkRules(); err != nil {
		return false, fmt.Errorf("read the bounds this machine holds on the passage: %w", err)
	} else if present {
		return true, nil
	}
	if _, present, err := executor.ReadUnitFile(linkRulesUnitPath); err != nil {
		return false, fmt.Errorf("read the unit that puts the bounds back at boot: %w", err)
	} else if present {
		return true, nil
	}
	_, present, err := executor.LinkLoopbackPolicy()
	if err != nil {
		return false, fmt.Errorf("read the host relaxation the passage declares: %w", err)
	}
	return present, nil
}

// poseLinkBounds writes and applies the bounds of one role, in the order this
// file fixes once.
//
// The order is an argument and not a habit:
//
//  1. the host relaxation comes first on the initiator, because the redirection
//     written next sends approved traffic towards an address the routing layer
//     would otherwise discard — a rule that cannot work is worse than a rule
//     that is not there yet;
//  2. the table is applied second, which is the moment this passage becomes
//     bounded;
//  3. the unit is written and enabled last, because what it does is put the two
//     files above back at the next boot, and there is nothing to put back until
//     they exist.
//
// Nothing of the passage can carry anything while this runs: a junction poses
// its bounds before it writes its peer, so during every step above the interface
// has no peer at all.
func poseLinkBounds(executor Executor, where linkPlacement, servicePort int) error {
	if where.goesOut {
		if err := executor.WriteLinkLoopbackPolicy(renderLinkLoopbackPolicy()); err != nil {
			return fmt.Errorf("apply the host relaxation the junction declares: %w", err)
		}
	}
	if err := executor.WriteLinkRules(renderLinkRules(where, servicePort)); err != nil {
		return fmt.Errorf("bound the passage to the approved service: %w", err)
	}
	if err := executor.WriteUnitFile(linkRulesUnitPath, renderLinkRulesUnit(where)); err != nil {
		return fmt.Errorf("write the unit that puts the bounds back at boot: %w", err)
	}
	if err := executor.EnableLinkRulesAtBoot(); err != nil {
		return fmt.Errorf("make this machine put the bounds back after a reboot: %w", err)
	}
	return nil
}

// removeLinkBounds takes them away, in the exact inverse order, and takes away
// only what this machine was found holding.
//
// It runs after the peer is gone rather than before it, which is the mirror of
// the rule above: the bounds are posed before a peer exists and removed once no
// peer is left, so there is no instant of either operation in which this machine
// holds a peer that nothing bounds. Removing them first would produce exactly
// that instant.
func removeLinkBounds(executor Executor, state linkBoundsState) error {
	if state.unitPresent {
		if err := executor.DisableLinkRulesAtBoot(); err != nil {
			return fmt.Errorf("stop putting the bounds back after a reboot: %w", err)
		}
		if err := executor.RemoveUnitFile(linkRulesUnitPath); err != nil {
			return fmt.Errorf("remove the unit that put the bounds back at boot: %w", err)
		}
	}
	if state.rulesPresent {
		if err := executor.RemoveLinkRules(); err != nil {
			return fmt.Errorf("remove the bounds of the passage: %w", err)
		}
	}
	if state.policyPresent {
		if err := executor.RemoveLinkLoopbackPolicy(); err != nil {
			return fmt.Errorf("remove the host relaxation the junction declared: %w", err)
		}
	}
	return nil
}

// linkListenerServiceRulePrefix is the exact opening of the one line of a
// listener's table that names the approved service port, built from the very
// constants that line is rendered from.
//
// It exists because another contract asks this table a question: the route of
// `#103` publishes a name whose backend is the peer of the tunnel, and the port
// it names has to be the port an approved junction already bounds. That fact
// lives here and nowhere else — the description of the interface carries the
// peer and its single /32 and no port at all — so this is where it is read back
// from. A test holds the prefix and the renderer together: it appears exactly
// once in a rendered listener table, and the port read through it is the port
// that table was rendered for.
func linkListenerServiceRulePrefix() string {
	return fmt.Sprintf("%s ip daddr %s tcp dport ", linkOutputScope, linkInitiatorAddress)
}

// approvedServicePort reads back the single port a listener's bounding table
// lets through the passage, or says that no such line is there.
//
// It reads the root-owned file the junction of `#97` wrote and this machine
// loaded into its kernel in the same effect, which is the honest source: it is
// the machine's own state rather than a claim of the document being applied, and
// nothing but this Auxiliary may write it.
func approvedServicePort(rules []byte) (int, bool) {
	for _, line := range linkRuleLines(rules) {
		rest, found := strings.CutPrefix(line, linkListenerServiceRulePrefix())
		if !found {
			continue
		}
		named, accepted := strings.CutSuffix(rest, " accept")
		if !accepted {
			return 0, false
		}
		port, err := strconv.Atoi(named)
		if err != nil {
			return 0, false
		}
		return port, true
	}
	return 0, false
}

// linkRuleLines is every rule one rendered table carries, with the chain
// declarations, the comments and the braces left out.
//
// It exists so that the property this file opens with — no rule without an
// interface scope — is read from the bytes that are actually written rather than
// from a list somebody kept up to date beside them.
func linkRuleLines(rules []byte) []string {
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
