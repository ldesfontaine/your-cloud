package auxiliary

import (
	"strconv"
	"strings"
	"testing"
)

// This file holds the confinement table itself: what it says, what it cannot
// say, and where the one value inside it comes from.
//
// The table is read here as a reviewer reads a firewall — every line, in order,
// with the question "what does this grant" asked of each of them. The answer has
// to be "nothing" for all three, because a table whose chain policy is accept and
// which drops only what one account emits cannot open anything this machine was
// not already doing.

// TestTheEgressTableRefusesEverythingTheServiceAccountEmits is the table quoted
// whole, as the contract's own sentence in nftables.
//
// The expected text below is the entire file rather than a list of lines it must
// contain. A rule added to it by a future change — an exception towards a
// registry, a name server, a neighbour of the LAN — fails this check by existing,
// which is precisely the failure a silent exception would otherwise be.
func TestTheEgressTableRefusesEverythingTheServiceAccountEmits(t *testing.T) {
	t.Parallel()
	const expected = `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
#
# This table only ever takes traffic away from one service account. Its chain
# carries an accept policy and drops what that account may not emit, so nothing
# here can grant this machine anything it did not already do. Every rule below is
# scoped to that account, and there is no exception.
#
# The confined account is your-cloud-svc-vaultwarden.
add table inet your-cloud-egress
delete table inet your-cloud-egress
table inet your-cloud-egress {
	chain output {
		type filter hook output priority filter; policy accept;

		# The loopback of this machine, and it grants nothing outward. The sheet
		# of the account below publishes on the loopback alone, so this is the
		# line by which the port a human approved answers the machine it lives
		# on — the local verification of a deployment included. Nothing beyond
		# this host is reachable through it.
		meta skuid 993 oifname "lo" accept

		# The replies of connections somebody else opened towards this service,
		# and the whole of what may leave this machine on its behalf. The related
		# state is deliberately not accepted beside the established one: what the
		# contract names is replies, and an ICMP error carried on behalf of a
		# confined account is not one.
		meta skuid 993 ct state established accept

		# Everything else this account emits, in one line and with no exception
		# above it: no neighbour of the LAN, no registry, no name server, no mail
		# relay. A new connection this service opens is refused wherever it was
		# going, which is what makes "aucun voisin du LAN n'est joignable depuis
		# le service" a fact of this machine rather than a claim about a network.
		meta skuid 993 drop
	}
}
`
	table := string(renderEgressRules(vaultwardenPlacement, fixtureAccountIdentifier))
	if table != expected {
		t.Fatalf("the confinement table is not the one this contract fixes:\n%s", table)
	}
	if table != string(renderEgressRules(vaultwardenPlacement, fixtureAccountIdentifier)) {
		t.Fatal("the confinement table is not the same bytes twice, so idempotence cannot be read from it")
	}
}

// TestNoRuleOfTheEgressTableIsWrittenWithoutItsAccountScope reads the property
// this table rests on from the bytes that are actually written.
//
// A rule without `meta skuid` would apply to every process of this machine, which
// is the one way a confinement of one account could become a firewall of a host
// nobody approved. There is no exception here and there is no line naming one:
// unlike the passage's own table, which carries a single deliberately unscoped
// statement, every rule of this one is scoped.
func TestNoRuleOfTheEgressTableIsWrittenWithoutItsAccountScope(t *testing.T) {
	t.Parallel()
	rules := renderEgressRules(vaultwardenPlacement, fixtureAccountIdentifier)
	lines := egressRuleLines(rules)
	if len(lines) != 3 {
		t.Fatalf("the confinement table carries %d rules rather than three: %q", len(lines), lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, egressAccountScope+" ") {
			t.Fatalf("a rule of the confinement table is not scoped to the account: %q", line)
		}
	}
	// The last word of the table is a drop, and the two lines above it are the two
	// statements the contract allows. Reading them in order is how "except
	// loopback and established replies" is held rather than assumed.
	if !strings.HasSuffix(lines[0], `oifname "lo" accept`) {
		t.Fatalf("the first rule is not the loopback statement: %q", lines[0])
	}
	if !strings.HasSuffix(lines[1], "ct state established accept") {
		t.Fatalf("the second rule is not the established replies statement: %q", lines[1])
	}
	if !strings.HasSuffix(lines[2], "drop") {
		t.Fatalf("the table does not end on a drop: %q", lines[2])
	}
	// Nothing this product ever writes into this table is a destination: an
	// exception towards an address would be exactly the silent widening the
	// contract refuses.
	for _, forbidden := range []string{"daddr", "dport", "accept\n\t\tmeta skuid 993 drop\n\t\tmeta"} {
		if strings.Contains(string(rules), forbidden) {
			t.Fatalf("the confinement table names %q:\n%s", forbidden, rules)
		}
	}
}

// TestTheConfinedAccountIsReadFromTheMachineAndNeverFromAPlan holds the one
// value inside the table to its source.
//
// An account identifier is allocated by the machine that creates the account, so
// it is neither a field of any document nor a constant of a placement. Two hosts
// that gave the same account two identifiers therefore render two different
// tables — and each of them confines its own account, which is the property that
// would be lost if the number were ever frozen into the profile.
func TestTheConfinedAccountIsReadFromTheMachineAndNeverFromAPlan(t *testing.T) {
	t.Parallel()
	first := string(renderEgressRules(vaultwardenPlacement, 993))
	second := string(renderEgressRules(vaultwardenPlacement, 1042))
	if first == second {
		t.Fatal("two machines with two identifiers rendered one table")
	}
	if !strings.Contains(second, egressAccountScope+" 1042 drop") {
		t.Fatalf("the table does not confine the identifier this machine gave:\n%s", second)
	}
	if strings.Contains(second, " 993") {
		t.Fatalf("the table carries an identifier this machine never gave:\n%s", second)
	}
	// The identifier is written as an integer and never as text of a document, so
	// there is nothing in this file a value could be smuggled through.
	if strings.Contains(first, strconv.Quote("993")) {
		t.Fatalf("the identifier reached the table as text:\n%s", first)
	}
}

// TestTheEgressUnitPutsTheConfinementBackBeforeAnythingCanStart holds the lesson
// the passage learned on a real machine, over the other table.
//
// A table loaded with `nft -f` lives in the kernel and not on disk. Without this
// unit the first reboot of a machine would bring the confined service back with
// nothing confining it, and no report would say so — which is the shape of every
// silent failure this product exists to refuse. What the unit is held to here is
// the ordering that makes it useful: it applies the table before any network
// exists, and therefore long before the lingering user manager that starts the
// service.
func TestTheEgressUnitPutsTheConfinementBackBeforeAnythingCanStart(t *testing.T) {
	t.Parallel()
	unit := string(renderEgressRulesUnit())
	for _, line := range []string{
		"Before=network-pre.target",
		"ConditionPathExists=" + egressRulesPath,
		"ExecStart=" + nftProgram + " --file " + egressRulesPath,
		"WantedBy=sysinit.target",
		"Type=oneshot",
	} {
		if !strings.Contains(unit, line) {
			t.Fatalf("the confinement unit does not declare %q:\n%s", line, unit)
		}
	}
	if unit != string(renderEgressRulesUnit()) {
		t.Fatal("the confinement unit is not the same bytes twice")
	}
	// It names the table's own file and nothing else: a unit that loaded a file
	// another plan writes is exactly what left the passage's listener unbounded
	// after its first reboot.
	if strings.Contains(unit, linkRulesPath) || strings.Contains(unit, linkLoopbackPolicyPath) {
		t.Fatalf("the confinement unit names a file another plan writes:\n%s", unit)
	}
	if egressRulesUnitName == linkRulesUnitName || egressTableName == linkTableName {
		t.Fatal("the confinement and the passage's bounds share a name")
	}
}
