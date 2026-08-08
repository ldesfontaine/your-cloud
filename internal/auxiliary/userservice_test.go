package auxiliary

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/plan"
	"github.com/ldesfontaine/your-cloud/internal/servicedefinition"
)

// This file is the third door read the way a reviewer reads it: what a definition
// becomes on a machine, what it can never become, and what survives a removal.
//
// Two claims run through all of it. The first is that nothing a user wrote ever
// becomes a host path or an account name — everything the machine owns derives
// from a slug this package validated itself, and the host paths are the home
// joined with container paths the definition already normalised. The second is
// that a value this machine generated never leaves it: the fake draws sentences
// instead of plausible secrets exactly so that "it did not travel" is a search
// through everything a run produced rather than an inspection of the fields
// somebody thought to check.

// The two revisions of one service used where a property is about a revision
// changing rather than about one revision being placed. They declare no
// interpolation, so their plans carry no origin — the agreement check holds that
// in both directions and it is exercised by the reference definition above.
const (
	fixtureTwoSecretsDefinition = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":8080,"volumes":["/srv/notes"],"tmpfs":[],"environment":[],` +
		`"secret_keys":["LAB_NOTES_ADMIN_TOKEN","LAB_NOTES_SESSION_KEY"]}`
	fixtureOneSecretDefinition = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":8080,"volumes":["/srv/notes"],"tmpfs":[],"environment":[],` +
		`"secret_keys":["LAB_NOTES_ADMIN_TOKEN"]}`
	fixtureNoVolumeDefinition = `{"schema_version":1,"slug":"lab-notes",` +
		`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
		`"container_port":80,"volumes":[],"tmpfs":[],"environment":[],"secret_keys":[]}`
)

// approvedUserServiceOf is the nominal subject over any definition a case wrote,
// so that a property about a revision changing is exercised through the whole
// chain — the Controller's own builder, the freeze, the signed pair and the bytes
// travelling beside it — rather than through a placement a test derived itself.
func approvedUserServiceOf(
	t *testing.T,
	operation, document string,
	port int,
	originHost string,
) (*approval.Acceptance, *Input) {
	t.Helper()
	definition, err := servicedefinition.Decode([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	pair, err := plan.BuildUserServicePair(operation, fixtureInfrastructure, fixtureMachine,
		definition, fixtureUserImageDigest, port, originHost)
	if err != nil {
		t.Fatal(err)
	}
	accepted, input := approvedFrozenPair(operation, frozenV2(t, pair))
	input.DefinitionDocument = []byte(document)
	return accepted, input
}

// TestTheSheetOfTheReferenceDefinitionIsTheOneThisContractFixes is the sheet of
// the third door quoted whole, over the very definition the two implementations
// hold their deterministic vectors against.
//
// The expected text below is the entire file rather than a list of lines it must
// contain, exactly as the confinement table is. A control that stopped being
// written, a volume that gained a second spelling, an origin that stopped being
// interpolated or an environment file that appeared where no key is declared all
// fail this check by existing.
func TestTheSheetOfTheReferenceDefinitionIsTheOneThisContractFixes(t *testing.T) {
	t.Parallel()
	const expected = `# Written by your-cloud auxiliary from one approved plan. Do not edit: this
# machine compares this file byte for byte against the plan it is given, and an
# edit here is a drift that requires a new approved plan rather than a repair.
[Unit]
Description=Your Cloud managed lab-notes user service

[Container]
Image=registry.lab.your-cloud.test/your-cloud/lab-notes@sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ContainerName=your-cloud-user-lab-notes
PublishPort=127.0.0.1:8080:8080
Pull=never
ReadOnly=true
NoNewPrivileges=true
DropCapability=ALL
Volume=/var/lib/your-cloud-user-lab-notes/volumes/srv/notes:/srv/notes:rw
Volume=/var/lib/your-cloud-user-lab-notes/volumes/var/lib/lab-notes:/var/lib/lab-notes:rw
Environment=LAB_NOTES_TITLE=Your Cloud lab notes
Environment=LAB_NOTES_ORIGIN=https://notes.lab.your-cloud.test/
Environment=LAB_NOTES_READ_ONLY=1
EnvironmentFile=/var/lib/your-cloud-user-lab-notes/secrets.env
Tmpfs=/tmp:rw,mode=1777

[Service]
Restart=on-failure

[Install]
WantedBy=default.target
`
	sheet := string(renderSheet(fixtureUserPlacement(t), fixturePort, fixtureUserOriginHost))
	if sheet != expected {
		t.Fatalf("the sheet of the third door is not the one this contract fixes:\n%s", sheet)
	}
	// The image listens above 1024, so the sysctl of the low ports is absent: it is
	// a function of the definition's own port and never a constant of a door, and a
	// control that grants nothing still reads as a control that was needed.
	if strings.Contains(sheet, "Sysctl=") {
		t.Fatalf("the sheet carries a sysctl this image does not need:\n%s", sheet)
	}
	if sheet != string(renderSheet(fixtureUserPlacement(t), fixturePort, fixtureUserOriginHost)) {
		t.Fatal("the sheet is not the same bytes twice, so idempotence cannot be read from it")
	}
}

// TestTheLowPortSysctlIsAFunctionOfTheDeclaredPortAndNeverOfADoor holds the one
// line the sheet gains from a definition rather than from a profile.
func TestTheLowPortSysctlIsAFunctionOfTheDeclaredPortAndNeverOfADoor(t *testing.T) {
	t.Parallel()
	low, err := servicedefinition.Decode([]byte(fixtureNoVolumeDefinition))
	if err != nil {
		t.Fatal(err)
	}
	sheet := string(renderSheet(
		userServicePlacementOf(low, fixtureUserImageDigest, ""), fixturePort, ""))
	if !strings.Contains(sheet, "Sysctl=net.ipv4.ip_unprivileged_port_start=0") {
		t.Fatalf("a definition listening below 1024 got no namespace-scoped sysctl:\n%s", sheet)
	}
	// A definition that keeps nothing and generates nothing carries neither a
	// volume nor an environment file, because both would read as something it needed.
	for _, forbidden := range []string{"Volume=", "EnvironmentFile=", "Environment=", "Tmpfs="} {
		if strings.Contains(sheet, forbidden) {
			t.Fatalf("the sheet declares %q for a definition that asked for none:\n%s", forbidden, sheet)
		}
	}
	if !strings.Contains(sheet, "ReadOnly=true") {
		t.Fatalf("the sheet of the third door stopped serving read-only:\n%s", sheet)
	}
}

// TestNothingAUserWroteBecomesAHostPathOrAnAccountName is the first closing
// criterion of this issue, read over definitions that differ by one character.
//
// The derivation has to be injective without an escape, a fallback or a
// fingerprint, and the neighbouring cases below are where a derivation that
// concatenated carelessly would collide: two slugs where one opens the other, two
// container paths where one opens the other, and a slug and a path traded against
// one another. Every host path of every case is collected into one set, and two
// cases sharing a directory is the failure.
func TestNothingAUserWroteBecomesAHostPathOrAnAccountName(t *testing.T) {
	t.Parallel()
	neighbours := []struct {
		slug    string
		volumes string
	}{
		{slug: "a", volumes: `["/b"]`},
		{slug: "ab", volumes: `["/b"]`},
		{slug: "a", volumes: `["/b-c"]`},
		{slug: "a", volumes: `["/b/c"]`},
		{slug: "note", volumes: `["/srv/notes"]`},
		{slug: "notes", volumes: `["/srv/note"]`},
		{slug: "notes", volumes: `["/srv/note","/srv/notes"]`},
		// The three subtrees of a home are names a definition could try to take, and
		// they must land under the volumes root like every other declared path
		// rather than beside the archives or the values.
		{slug: "notes", volumes: `["/snapshots","/secrets","/volumes"]`},
	}
	held := map[string]string{}
	for _, neighbour := range neighbours {
		document := `{"schema_version":1,"slug":"` + neighbour.slug + `",` +
			`"image_repository":"registry.lab.your-cloud.test/your-cloud/lab-notes",` +
			`"container_port":8080,"volumes":` + neighbour.volumes +
			`,"tmpfs":[],"environment":[],"secret_keys":[]}`
		definition, err := servicedefinition.Decode([]byte(document))
		if err != nil {
			t.Fatalf("the neighbouring definition %q is not one this product accepts: %v", document, err)
		}
		where := userServicePlacementOf(definition, fixtureUserImageDigest, "")

		// The account is the prefix and the slug, and nothing else of the document
		// reaches it: not the repository, not a port, not a path.
		if where.account != "your-cloud-user-"+neighbour.slug {
			t.Fatalf("the account of %q is %q", neighbour.slug, where.account)
		}
		if len(where.account) > 32 {
			t.Fatalf("the account %q does not fit a user name of this machine", where.account)
		}
		if where.home != "/var/lib/"+where.account {
			t.Fatalf("the home of %q is %q", neighbour.slug, where.home)
		}
		// Every path this placement names lives under that one home, so no value of
		// any document can put a directory of this service anywhere else on the host.
		for _, path := range append(where.durableDirectories(),
			where.snapshotDirectory, where.secretsDirectory(), where.environmentFilePath(),
			where.unitPath(), where.archivePath(fixtureSnapshotSlot)) {
			if !strings.HasPrefix(path, where.home+"/") {
				t.Fatalf("the placement of %q names %q outside its own home", neighbour.slug, path)
			}
		}
		// A host path is the home's volumes root joined with the container path
		// verbatim, and there is no second way to spell one.
		for _, mount := range where.volumes {
			expected := where.home + "/volumes" + mount.container
			if mount.host != expected {
				t.Fatalf("the host path of %q %q is %q rather than %q",
					neighbour.slug, mount.container, mount.host, expected)
			}
			// One slug and one container path always derive one directory, whichever
			// revision declared it — that is what makes the data of a service survive
			// a revision. Two *different* pairs deriving one directory is the
			// collision this criterion refuses.
			pair := neighbour.slug + " " + mount.container
			if taken, held := held[mount.host]; held && taken != pair {
				t.Fatalf("%q and %q derive the same host path %q", taken, pair, mount.host)
			}
			held[mount.host] = pair
		}
	}
}

// TestAnArchiveOfTheThirdDoorCoversEveryVolumeAndNoSecret holds the two sentences
// the contract writes about what an archive of a user service is.
//
// The archived root is the one directory every volume lives under, so a snapshot
// is a single coherent state of all of them rather than one file per mount; and
// the generated values are a sibling of that root rather than a part of it, so
// they are outside every archive by construction rather than by a rule somebody
// has to remember.
func TestAnArchiveOfTheThirdDoorCoversEveryVolumeAndNoSecret(t *testing.T) {
	t.Parallel()
	where := fixtureUserPlacement(t)
	if len(where.volumes) < 2 {
		t.Fatal("the reference definition stopped declaring more than one volume")
	}
	for _, mount := range where.volumes {
		if !strings.HasPrefix(mount.host, where.dataDirectory+"/") {
			t.Fatalf("the volume %q lives outside the archived root %q", mount.host, where.dataDirectory)
		}
	}
	for _, apart := range []string{
		where.secretsDirectory(), where.environmentFilePath(), where.snapshotDirectory,
	} {
		if strings.HasPrefix(apart, where.dataDirectory+"/") || apart == where.dataDirectory {
			t.Fatalf("%q is inside the tree an archive walks", apart)
		}
	}
}

// TestASnapshotOfAHomeWithoutVolumesIsRefusedBeforeAnyEffect holds the contract's
// own sentence: a definition without a volume has nothing to archive, and the
// operation reads that on the machine rather than in a document it was never
// handed.
func TestASnapshotOfAHomeWithoutVolumesIsRefusedBeforeAnyEffect(t *testing.T) {
	t.Parallel()
	executor := deployedUserServiceMachine(t, fixturePort)
	executor.dataPresent = false
	accepted, input := approvedUserArchive(t, plan.OperationSnapshotService)

	if _, err := Apply(executor, accepted, input); err == nil {
		t.Fatal("a snapshot of a home holding no volumes was performed")
	} else if !strings.Contains(err.Error(), "there is nothing to archive") {
		t.Fatalf("it was refused for another reason: %v", err)
	}
	if len(executor.effects) != 0 {
		t.Fatalf("a refused snapshot touched this machine: %q", executor.effects)
	}
}

// TestADefinitionAlteredByOneByteIsRefusedBeforeThisMachineIsRead is the third
// step of the contract's own trajectory, held here.
//
// The plan is untouched and perfectly valid; what changed is one character of the
// document travelling beside it. The digest is rebuilt here from the parsed fields
// of those very bytes, so the alteration is caught by this machine rather than
// trusted away — and it is caught before anything of this host is read, let alone
// written.
func TestADefinitionAlteredByOneByteIsRefusedBeforeThisMachineIsRead(t *testing.T) {
	t.Parallel()
	for name, altered := range map[string]string{
		"one character of a value": strings.Replace(fixtureUserDefinitionDocument,
			"Your Cloud lab notes", "Your Cloud Lab notes", 1),
		"one volume renamed": strings.Replace(fixtureUserDefinitionDocument,
			"/srv/notes", "/srv/note", 1),
		"one secret key added": strings.Replace(fixtureUserDefinitionDocument,
			`"secret_keys":["LAB_NOTES_ADMIN_TOKEN"]`,
			`"secret_keys":["LAB_NOTES_ADMIN_TOKEN","LAB_NOTES_EXTRA"]`, 1),
	} {
		executor := userServiceMachine()
		accepted, input := approvedUserService(t, plan.OperationDeployUserService, fixturePort)
		if altered == fixtureUserDefinitionDocument {
			t.Fatalf("%s altered nothing", name)
		}
		input.DefinitionDocument = []byte(altered)

		application, err := Apply(executor, accepted, input)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if application != nil {
			t.Fatalf("%s returned an application: %+v", name, application)
		}
		if !strings.Contains(err.Error(), "does not carry the digest that names it") {
			t.Fatalf("%s was refused for another reason than its digest: %v", name, err)
		}
		if len(executor.effects) != 0 || len(executor.reads) != 0 {
			t.Fatalf("%s reached the machine: %q %q", name, executor.effects, executor.reads)
		}
	}
}

// TestADefinitionTravelsExactlyWithThePlanThatPinsOne holds the framing rule in
// both directions.
//
// A plan of the third door without its definition cannot be placed at all — the
// account, the home and every path would have to be invented — and a definition
// beside a plan that pins none is a document nothing in the run reads, therefore a
// document nobody verified. Both are refused before this machine is read.
func TestADefinitionTravelsExactlyWithThePlanThatPinsOne(t *testing.T) {
	t.Parallel()
	missing := userServiceMachine()
	accepted, input := approvedUserService(t, plan.OperationDeployUserService, fixturePort)
	input.DefinitionDocument = nil
	if _, err := Apply(missing, accepted, input); err == nil {
		t.Fatal("a user service plan was placed without the revision it names")
	} else if !strings.Contains(err.Error(), "cannot be placed without the revision it names") {
		t.Fatalf("it was refused for another reason: %v", err)
	}
	if len(missing.effects) != 0 || len(missing.reads) != 0 {
		t.Fatalf("it reached the machine: %q %q", missing.effects, missing.reads)
	}

	stray := deployedServiceMachine(t, fixturePort)
	strayApproval, strayInput := approvedService(t, plan.OperationRemoveWebService, fixturePort)
	strayInput.DefinitionDocument = []byte(fixtureUserDefinitionDocument)
	if _, err := Apply(stray, strayApproval, strayInput); err == nil {
		t.Fatal("a definition travelled beside a plan pinning none and was accepted")
	} else if !strings.Contains(err.Error(), "which pins none") {
		t.Fatalf("it was refused for another reason: %v", err)
	}
	if len(stray.effects) != 0 || len(stray.reads) != 0 {
		t.Fatalf("it reached the machine: %q %q", stray.effects, stray.reads)
	}
}

// TestRemovingThenRedeployingFindsTheSameDataAndTheSameSecrets is the second
// closing criterion of this issue, and it is the contract's "recréation contrôlée"
// read as two plans a human approves.
//
// The two operations run against one machine, in order, exactly as they would on a
// host: a removal that keeps what the user owns, and a deployment that finds it.
// What must be identical is the data and every generated value; what must be new
// is the container.
func TestRemovingThenRedeployingFindsTheSameDataAndTheSameSecrets(t *testing.T) {
	t.Parallel()
	where := fixtureUserPlacement(t)
	executor := deployedUserServiceMachine(t, fixturePort)
	before := map[string]string{}
	for path, value := range executor.secrets {
		before[path] = value
	}
	drawnBefore := executor.secretsGenerated

	removal, removalInput := approvedUserService(t, plan.OperationRemoveUserService, fixturePort)
	removed, err := Apply(executor, removal, removalInput)
	if err != nil {
		t.Fatalf("removing a present user service was refused: %v", err)
	}
	if !removed.Changed || removed.ServiceState != ServiceStateAbsent {
		t.Fatalf("the removal announced the wrong state: %+v", removed)
	}
	// The report names what survives rather than leaving a reader to assume it.
	if removed.DataPath != where.dataDirectory || removed.SecretsPath != where.secretsDirectory() {
		t.Fatalf("the removal did not name what this machine keeps: %+v", removed)
	}
	if !executor.dataPresent || executor.dataContent != fixtureSecrets {
		t.Fatalf("the removal took the data away: %t %q", executor.dataPresent, executor.dataContent)
	}
	if len(executor.secrets) != len(before) {
		t.Fatalf("the removal took a generated value away: %v", executor.secrets)
	}
	if executor.image != "" || executor.active {
		t.Fatalf("the removal left the service running: %q %t", executor.image, executor.active)
	}

	deployment, deploymentInput := approvedUserService(t, plan.OperationDeployUserService, fixturePort)
	applied, err := Apply(executor, deployment, deploymentInput)
	if err != nil {
		t.Fatalf("redeploying the removed user service was refused: %v", err)
	}
	if !applied.Changed || applied.ServiceState != ServiceStateActive {
		t.Fatalf("the redeployment announced the wrong state: %+v", applied)
	}
	if executor.dataContent != fixtureSecrets {
		t.Fatalf("the redeployment did not find the data it left: %q", executor.dataContent)
	}
	if executor.secretsGenerated != drawnBefore {
		t.Fatalf("the redeployment generated a value again: %d draws rather than %d",
			executor.secretsGenerated, drawnBefore)
	}
	for path, value := range before {
		if executor.secrets[path] != value {
			t.Fatalf("the value of %q changed across a removal and a deployment", path)
		}
	}
	// The container is new: the image was fetched again and the service started
	// again, which is exactly what "same data, same secrets, new container" means.
	if executor.image != where.image || !executor.active {
		t.Fatalf("the redeployment did not put a container back: %q %t", executor.image, executor.active)
	}
	if len(executor.pulled) != 1 || len(executor.startedServices) != 1 {
		t.Fatalf("the redeployment did not create a container: %v %v",
			executor.pulled, executor.startedServices)
	}
}

// TestTheNominalUserServiceDeploymentPosesEveryEffectInTheOrderTheContractFixes
// reads the deployment the way a report will have to explain it.
//
// The order is the security argument and it is asserted whole: the directories and
// the values before anything runs, this account leaving the shared table for the
// length of the fetch, the table posed again before the sheet is written, and the
// bounded local verification last. Every host directory the placement derived is
// asserted to have reached the machine, because that is where "the host paths are
// the home joined with the container paths" stops being a derivation and becomes
// a set of directories somebody owns.
func TestTheNominalUserServiceDeploymentPosesEveryEffectInTheOrderTheContractFixes(t *testing.T) {
	t.Parallel()
	where := fixtureUserPlacement(t)
	executor := userServiceMachine()
	accepted, input := approvedUserService(t, plan.OperationDeployUserService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("the nominal user service deployment was refused: %v", err)
	}
	if !application.Changed || application.ServiceState != ServiceStateActive {
		t.Fatalf("the first user service application announced no change: %+v", application)
	}
	if application.UnitPath != where.unitPath() || application.LocalPort != fixturePort {
		t.Fatalf("the application named another instance: %+v", application)
	}

	expected := []string{
		"EnsureServiceData", "EnsureServiceSecrets", "PullImage",
		"WriteEgressRules", "WriteUnitFile", "EnableEgressRulesAtBoot",
		"WriteUnitFile", "ReloadUserUnits", "StartService",
	}
	if strings.Join(executor.effects, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected effects: %q", executor.effects)
	}
	// The directories this machine now owns are the durable root and one per
	// declared volume, and no other path at all.
	if strings.Join(executor.dataDirectories, ",") != strings.Join(where.durableDirectories(), ",") {
		t.Fatalf("the deployment held directories this placement never derived: %q", executor.dataDirectories)
	}
	if len(executor.dataDirectories) != 1+len(where.volumes) {
		t.Fatalf("the deployment held %d directories for %d volumes",
			len(executor.dataDirectories), len(where.volumes))
	}
	if len(executor.pulled) != 1 || executor.pulled[0] != where.image {
		t.Fatalf("another image than the approved one was fetched: %v", executor.pulled)
	}
	if len(executor.accountsCreated) != 0 {
		t.Fatalf("an account was created on a machine that already held one: %v", executor.accountsCreated)
	}
	// The local verification is the status alone: what an application a user chose
	// answers a plain request with is described by no plan of this door.
	if len(executor.probedPorts) != 1 || executor.probedPorts[0] != fixturePort {
		t.Fatalf("the announced state was not verified locally: %v", executor.probedPorts)
	}
	if len(executor.probedContentTypes) != 1 || executor.probedContentTypes[0] != "" {
		t.Fatalf("the local verification asked something of the answer: %v", executor.probedContentTypes)
	}
	if string(executor.held(where.unitPath())) != string(renderSheet(where, fixturePort, fixtureUserOriginHost)) {
		t.Fatalf("the sheet this machine holds is not the one the definition renders:\n%s",
			executor.held(where.unitPath()))
	}

	// Replaying the very same plan is not an action: the approved state holds down
	// to the bytes of the sheet, the volumes, the values and the confinement.
	replay, replayInput := approvedUserService(t, plan.OperationDeployUserService, fixturePort)
	before := len(executor.effects)
	replayed, err := Apply(executor, replay, replayInput)
	if err != nil {
		t.Fatalf("replaying the approved user service plan was refused: %v", err)
	}
	if replayed.Changed {
		t.Fatalf("replaying the approved plan announced a change: %+v", replayed)
	}
	if len(executor.effects) != before {
		t.Fatalf("replaying the approved plan touched the machine: %q", executor.effects[before:])
	}
}

// TestAKeyLeavingARevisionLeavesTheEnvironmentFileAndKeepsItsValue holds the two
// sentences the contract writes about a revision that stops declaring a key.
//
// Nothing of this product destroys a value, so the file survives under the home;
// and the environment file is rewritten from the keys the deployed revision
// declares, so the container stops receiving it. The two together are what makes
// "rien ne détruit une valeur" a property rather than a promise.
func TestAKeyLeavingARevisionLeavesTheEnvironmentFileAndKeepsItsValue(t *testing.T) {
	t.Parallel()
	where := userServicePlacementOfSlug(fixtureUserSlug)
	executor := userServiceMachine()

	first, firstInput := approvedUserServiceOf(t,
		plan.OperationDeployUserService, fixtureTwoSecretsDefinition, fixturePort, "")
	if _, err := Apply(executor, first, firstInput); err != nil {
		t.Fatalf("the first deployment of two declared keys was refused: %v", err)
	}
	if executor.secretsGenerated != 2 {
		t.Fatalf("the first deployment drew %d values for two keys", executor.secretsGenerated)
	}
	dropped := where.secretsDirectory() + "/LAB_NOTES_SESSION_KEY"
	kept := where.secretsDirectory() + "/LAB_NOTES_ADMIN_TOKEN"
	droppedValue := executor.secrets[dropped]
	keptValue := executor.secrets[kept]
	if droppedValue == "" || keptValue == "" {
		t.Fatalf("the first deployment generated no value for a declared key: %v", executor.secrets)
	}

	second, secondInput := approvedUserServiceOf(t,
		plan.OperationDeployUserService, fixtureOneSecretDefinition, fixturePort, "")
	if _, err := Apply(executor, second, secondInput); err != nil {
		t.Fatalf("the revision declaring one key was refused: %v", err)
	}
	if executor.secretsGenerated != 2 {
		t.Fatalf("the second revision generated a value again: %d draws", executor.secretsGenerated)
	}
	if executor.secrets[dropped] != droppedValue {
		t.Fatal("the value of a key a revision stopped declaring was destroyed")
	}
	if executor.secrets[kept] != keptValue {
		t.Fatal("the value of a key both revisions declare was replaced")
	}
	environment := executor.secretEnvironments[where.environmentFilePath()]
	if !strings.Contains(environment, "LAB_NOTES_ADMIN_TOKEN=") {
		t.Fatalf("the environment file lost a key the revision declares:\n%s", environment)
	}
	if strings.Contains(environment, "LAB_NOTES_SESSION_KEY") {
		t.Fatalf("the environment file still names a key the revision dropped:\n%s", environment)
	}
}

// TestTheAccountOfAUserServiceJoinsTheOneTableBesideTheDeliveredProfile holds the
// contract's own words — the account joins the single `inet your-cloud-egress`
// table — and the property that makes a shared table safe.
//
// Two things are read here and they are not the same. The table this machine ends
// up holding names both accounts, each with its own three scoped rules; and the
// table it held *while the image was being fetched* still named the account that
// was not being deployed. A deployment that lifted the whole table for the length
// of its own fetch would leave somebody else's service unconfined for that long,
// and no report would ever say so.
func TestTheAccountOfAUserServiceJoinsTheOneTableBesideTheDeliveredProfile(t *testing.T) {
	t.Parallel()
	user := fixtureUserPlacement(t)
	executor := userServiceMachine()
	// A machine already running the delivered private profile: its sheet is there,
	// so it is one of the accounts this machine confines.
	executor.hold(vaultwardenPlacement.unitPath(),
		renderSheet(vaultwardenPlacement, fixturePort+1, fixtureOriginHost))
	executor.egressRules = renderEgressRules(confinedAs(vaultwardenPlacement, executor.accountIdentifier))
	executor.egressRulesPresent = true
	executor.hold(egressRulesUnitPath, renderEgressRulesUnit())
	executor.egressAtBoot = true

	accepted, input := approvedUserService(t, plan.OperationDeployUserService, fixturePort)
	if _, err := Apply(executor, accepted, input); err != nil {
		t.Fatalf("deploying a user service beside the private profile was refused: %v", err)
	}

	if len(executor.egressWrites) != 2 {
		t.Fatalf("the deployment wrote the confinement %d times", len(executor.egressWrites))
	}
	fetching := string(executor.egressWrites[0])
	if !strings.Contains(fetching, VaultwardenAccount) {
		t.Fatalf("the table posed for the length of the fetch dropped another service:\n%s", fetching)
	}
	if strings.Contains(fetching, user.account) {
		t.Fatalf("the table posed for the length of the fetch still confined the fetching account:\n%s", fetching)
	}
	final := string(executor.egressWrites[1])
	for _, account := range []string{VaultwardenAccount, user.account} {
		if !strings.Contains(final, account) {
			t.Fatalf("the confinement this machine holds does not name %s:\n%s", account, final)
		}
	}
	if final != string(executor.egressRules) {
		t.Fatal("the table this machine holds is not the last one written")
	}
	// Six rules, three per account, and not one of them without its account scope:
	// a rule that lost its scope would be a confinement of one service becoming a
	// firewall of a host nobody approved.
	lines := egressRuleLines(executor.egressRules)
	if len(lines) != 6 {
		t.Fatalf("the shared table carries %d rules rather than six: %q", len(lines), lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, egressAccountScope+" ") {
			t.Fatalf("a rule of the shared table is not scoped to an account: %q", line)
		}
	}
	// The delivered profile's own sheet was not touched by a deployment of another
	// door: what this operation wrote is its own sheet and the shared table.
	if string(executor.held(vaultwardenPlacement.unitPath())) !=
		string(renderSheet(vaultwardenPlacement, fixturePort+1, fixtureOriginHost)) {
		t.Fatal("deploying a user service rewrote the sheet of another service")
	}
}

// TestAnImageThatWillNotServeReadOnlyIsAControlledFailureAndNeverARelaxation is
// the contract's fourth named limit, held on a machine.
//
// An image that cannot serve under the controls of this product fails, the
// approved rollback runs, and nothing anywhere relaxes ReadOnly. What the user
// does next is complete their definition and freeze a revision — the machine has
// no other answer and offers none.
func TestAnImageThatWillNotServeReadOnlyIsAControlledFailureAndNeverARelaxation(t *testing.T) {
	t.Parallel()
	executor := userServiceMachine()
	executor.failures["ProbeAnswers"] = errors.New("this image will not serve read-only")
	accepted, input := approvedUserService(t, plan.OperationDeployUserService, fixturePort)

	application, err := Apply(executor, accepted, input)
	if application != nil {
		t.Fatalf("a service that never answered was reported applied: %+v", application)
	}
	var controlled *ControlledFailure
	if !errors.As(err, &controlled) {
		t.Fatalf("an image that would not serve was not a controlled failure: %v", err)
	}
	if controlled.Outcome != OutcomeRolledBack {
		t.Fatalf("the approved rollback did not reach the state it describes: %+v", controlled)
	}
	if controlled.Operation != plan.OperationDeployUserService {
		t.Fatalf("the failure named another instance: %+v", controlled)
	}
	// The sheet this machine wrote — and the rollback then removed — carried every
	// control of the contract. Nothing in this flow can write one that does not.
	for _, line := range []string{"ReadOnly=true", "NoNewPrivileges=true", "DropCapability=ALL", "Pull=never"} {
		if !strings.Contains(string(executor.writtenUnit), line) {
			t.Fatalf("the sheet written before the failure dropped %q:\n%s", line, executor.writtenUnit)
		}
	}
	if executor.holds(fixtureUserPlacement(t).unitPath()) {
		t.Fatal("the rollback left the sheet of a service that never served")
	}
	// What the rollback keeps is what a removal keeps: the data and the values the
	// deployment generated survive a failure exactly as they survive a removal.
	if !executor.dataPresent || len(executor.secrets) == 0 {
		t.Fatalf("the rollback destroyed what this machine had generated: %t %v",
			executor.dataPresent, executor.secrets)
	}
}

// TestAFailedUserServiceRollbackObservesWhatTheUserStillOwns keeps the partial
// state a statement about the instance that was being applied.
//
// After a rollback that failed in its turn, what a human has to read about a
// service of the third door is what the user still owns and whether this machine
// still refuses what that service emits. Both are asked, neither is inferred from
// the other, and the sentence the failure renders carries them beside the four
// words every managed service is left holding.
func TestAFailedUserServiceRollbackObservesWhatTheUserStillOwns(t *testing.T) {
	t.Parallel()
	executor := deployedUserServiceMachine(t, fixturePort)
	executor.drop(fixtureUserPlacement(t).unitPath())
	executor.failures["ProbeAnswers"] = errors.New("the service never answered")
	executor.failures["RemoveImage"] = errors.New("the machine refused this effect")
	accepted, input := approvedUserService(t, plan.OperationDeployUserService, fixturePort)

	_, err := Apply(executor, accepted, input)
	var controlled *ControlledFailure
	if !errors.As(err, &controlled) {
		t.Fatalf("the failure was not a controlled one: %v", err)
	}
	if controlled.Outcome != OutcomePartial || controlled.Observed == nil {
		t.Fatalf("a rollback that failed in its turn was not named a partial state: %+v", controlled)
	}
	if controlled.Observed.Data != observedPresent {
		t.Fatalf("the observation says nothing true about the volumes: %+v", controlled.Observed)
	}
	if controlled.Observed.Egress == "" {
		t.Fatalf("the observation says nothing about the confinement: %+v", controlled.Observed)
	}
	if controlled.Observed.Archive != "" {
		t.Fatalf("the observation names an archive nobody looked at: %+v", controlled.Observed)
	}
	for _, word := range []string{"data ", "egress ", "account ", "container "} {
		if !strings.Contains(controlled.Error(), word) {
			t.Fatalf("the partial state does not say %q: %s", word, controlled.Error())
		}
	}
	// A partial state carries no generated value, here as everywhere else: what a
	// human is told is that this machine still holds them, never which they are.
	for _, value := range executor.secrets {
		if strings.Contains(controlled.Error(), value) {
			t.Fatalf("the partial state carried a generated value: %s", controlled.Error())
		}
	}
}

// TestAConfinedServiceWithoutVolumesIsStillObservedForItsConfinement holds the one
// word the third door made reachable on its own.
//
// A definition may declare no volume at all, and such a service is confined like
// every other. After a rollback that failed, whether this machine still refuses
// what it emits is exactly what has to be read — and the data it never had is not
// reported at all, because a word about something nobody looked at would be
// neither a fact nor an admission.
func TestAConfinedServiceWithoutVolumesIsStillObservedForItsConfinement(t *testing.T) {
	t.Parallel()
	executor := userServiceMachine()
	executor.failures["ProbeAnswers"] = errors.New("the service never answered")
	executor.failures["RemoveImage"] = errors.New("the machine refused this effect")
	accepted, input := approvedUserServiceOf(t,
		plan.OperationDeployUserService, fixtureNoVolumeDefinition, fixturePort, "")

	_, err := Apply(executor, accepted, input)
	var controlled *ControlledFailure
	if !errors.As(err, &controlled) {
		t.Fatalf("the failure was not a controlled one: %v", err)
	}
	if controlled.Observed == nil || controlled.Observed.Egress == "" {
		t.Fatalf("a confined service that keeps nothing was observed without its confinement: %+v", controlled)
	}
	if controlled.Observed.Data != "" {
		t.Fatalf("the observation names data this service never had: %+v", controlled.Observed)
	}
	if strings.Contains(controlled.Error(), "data ") {
		t.Fatalf("the partial state names data this service never had: %s", controlled.Error())
	}
	// Nothing of the durable machinery ran for a service that keeps nothing: no
	// directory was created and no archive directory exists to name.
	if len(executor.dataDirectories) != 0 {
		t.Fatalf("a service declaring no volume held directories anyway: %q", executor.dataDirectories)
	}
}

// TestALocalRouteMayNameAUserServiceAndNeverAPrivateOne holds the one reading the
// publication learns of the third door.
//
// The form of a route plan does not change and the refusal of the private door
// does not move: what changes is that the reading beneath them knows three doors.
// A user service's loopback port is a backend a local route may name — the choice
// of trajectory belongs to the placement a human approves — and a vault's is still
// refused, because that refusal was a decision of that profile.
func TestALocalRouteMayNameAUserServiceAndNeverAPrivateOne(t *testing.T) {
	t.Parallel()
	where := fixtureUserPlacement(t)
	executor := entrypointMachine()
	executor.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
	executor.hold(where.unitPath(), renderSheet(where, fixturePort, fixtureUserOriginHost))

	accepted, input := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)
	application, err := Apply(executor, accepted, input)
	if err != nil {
		t.Fatalf("a local route towards a user service was refused: %v", err)
	}
	if !application.Changed || application.RouteHost != fixtureRouteHost {
		t.Fatalf("the publication named another route: %+v", application)
	}

	// The same machine, with the port published by the delivered private profile
	// instead: the refusal is the private door's and it is unchanged.
	vault := entrypointMachine()
	vault.hold(entrypointPlacement.unitPath(), renderEntrypointSheet())
	vault.hold(vaultwardenPlacement.unitPath(), renderSheet(vaultwardenPlacement, fixturePort, fixtureOriginHost))
	refusedApproval, refusedInput := approvedRoute(t, plan.OperationPublishRoute, fixtureRouteHost, fixturePort)
	if _, err := Apply(vault, refusedApproval, refusedInput); err == nil {
		t.Fatal("a local route towards a vault was published")
	} else if !strings.Contains(err.Error(), "published by the passage, not by a local route") {
		t.Fatalf("it was refused for another reason: %v", err)
	}
}
