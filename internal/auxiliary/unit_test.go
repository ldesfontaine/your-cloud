package auxiliary

import (
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// TestTheQuadletSheetDeclaresOnlyTheControlsThisPalierOwes reads the sheet the
// way a report will have to explain it: every line is a control, and the fields
// that would widen the container are absent rather than set to a safe value.
func TestTheQuadletSheetDeclaresOnlyTheControlsThisPalierOwes(t *testing.T) {
	t.Parallel()
	document, err := plan.Decode(frozenPair(t, plan.OperationDeployOCIProbe, fixturePort).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	sheet := string(renderUnit(document))

	for _, line := range []string{
		"Image=" + plan.ProbeImageReference + "@" + plan.ProbeImageDigest,
		"ContainerName=" + containerName,
		"PublishPort=127.0.0.1:8080:80",
		"Pull=never",
		"ReadOnly=true",
		"NoNewPrivileges=true",
		"DropCapability=ALL",
		"Sysctl=net.ipv4.ip_unprivileged_port_start=0",
		"WantedBy=default.target",
	} {
		if !strings.Contains(sheet, line) {
			t.Fatalf("the sheet does not declare %q:\n%s", line, sheet)
		}
	}

	// None of these can come from a plan — the plan has no field for any of them
	// — so none of them may appear in a sheet either.
	for _, forbidden := range []string{
		"Volume=", "Mount=", "Device=", "Environment=", "EnvironmentFile=",
		"AddCapability=", "Privileged=", "User=root", "PodmanArgs=", "Exec=",
		"AutoUpdate=", "0.0.0.0", "::",
	} {
		if strings.Contains(sheet, forbidden) {
			t.Fatalf("the sheet declares %q:\n%s", forbidden, sheet)
		}
	}

	// The published port is bound to the loopback address of the contract, and
	// the tag-free pinned digest is the only identity of the image.
	if strings.Count(sheet, "PublishPort=") != 1 {
		t.Fatalf("the sheet publishes more than one port:\n%s", sheet)
	}
	if strings.Contains(sheet, plan.ProbeImageReference+":") {
		t.Fatalf("the sheet names the image by a tag:\n%s", sheet)
	}
}

// TestTheOnlyPlanValueThatReachesTheSheetIsThePort holds the transport rule at
// its narrowest: two plans that differ only by their port produce two sheets
// that differ only by that one line, so no plan-derived string can ride into the
// file beside the value that is allowed to.
func TestTheOnlyPlanValueThatReachesTheSheetIsThePort(t *testing.T) {
	t.Parallel()
	first, err := plan.Decode(frozenPair(t, plan.OperationDeployOCIProbe, 8080).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}
	second, err := plan.Decode(frozenPair(t, plan.OperationRemoveOCIProbe, 65535).PlanDocument)
	if err != nil {
		t.Fatal(err)
	}

	if string(renderUnit(first)) != string(renderUnit(first)) {
		t.Fatal("the sheet is not the same bytes twice, so idempotence cannot be read from it")
	}

	left := strings.Split(string(renderUnit(first)), "\n")
	right := strings.Split(string(renderUnit(second)), "\n")
	if len(left) != len(right) {
		t.Fatalf("two plans produced sheets of different shapes:\n%q\n%q", left, right)
	}
	differences := 0
	for index := range left {
		if left[index] != right[index] {
			differences++
			if !strings.HasPrefix(left[index], "PublishPort=") {
				t.Fatalf("a value other than the port reached the sheet: %q", left[index])
			}
		}
	}
	if differences != 1 {
		t.Fatalf("two plans differing by their port produced %d differences", differences)
	}
}
