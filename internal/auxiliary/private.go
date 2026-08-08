package auxiliary

import (
	"bytes"
	"fmt"
)

// This file is the deployment and the removal of a service whose data outlives
// its container.
//
// It is the stateless flow of `#91` plus three things, and it is written out
// rather than folded into that flow because each of the three changes what the
// operation *is*: a durable directory that the removal deliberately does not take
// away, a sheet carrying an origin and a volume, and a table that refuses
// everything the service's account emits. A deployment that reused the stateless
// path with three conditionals would be one function that answers "what does this
// leave behind" two different ways.
//
// Two values of a plan reach this file and no third: the loopback port and the
// origin host, both bounded by the plan validation before they arrive, and both
// travelling only into the sheet. The volume, the environment, the archive
// directory and the confinement table are constants of the placement, so no
// approvable value can move a write path or widen what the service may reach.

// deployPrivateService brings the machine to the state a private service plan
// describes, and says whether doing so changed anything.
//
// What "already held" means here is larger than for a stateless profile, and
// every part of it is read from the machine rather than remembered:
//
//   - the sheet, byte for byte, which embeds the origin and the volume;
//   - the service and the image the running container was created from, exactly
//     as the stateless flow reads them;
//   - the durable data directory *exists*. A deployed service whose data has
//     vanished is a drift and it is reapplied as one — the directory is created
//     again, empty, and the report says the operation changed this machine. It is
//     deliberately not treated as continuity: this Auxiliary has no way to know
//     what was in that directory, and a run that quietly recreated it while
//     announcing "nothing changed" would be a machine claiming data it does not
//     have;
//   - the confinement table and the unit that poses it again at boot, byte for
//     byte against what this machine's own account identifier renders. A flushed
//     table is a change the plan reapplies, never a repair nobody asked for.
//
// The order of the effects is the security argument of this operation and it is
// fixed here:
//
//  1. the account, if this machine has none;
//  2. the two directories the profile owns — the data under that account, the
//     archives under root alone;
//  3. the service is stopped, if it was running. It is stopped *before* the
//     confinement is lifted, so no instant of this flow has a running service
//     that nothing confines;
//  4. the confinement is lifted, if this machine held it. It has to be: the fetch
//     below runs as the service's own account, and the table refuses exactly what
//     fetching needs;
//  5. the pinned image is fetched — the one moment this operation talks to a
//     registry, explicit and with its own failure;
//  6. the confinement is posed again;
//  7. the sheet is written, the units are reloaded, the service is started and
//     the local verification proves the announced state.
//
// An update to a newer pin therefore performs three visible effects around the
// fetch — lift, fetch, pose — and never a silent exception inside a table that
// stayed up.
func deployPrivateService(executor Executor, capabilities Capabilities, subject instance) (*Application, bool, error) {
	where := subject.placement
	desired := renderSheet(where, subject.localPort, subject.originHost)
	path := where.unitPath()

	current, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}
	dataPresent, err := executor.ServiceDataPresent(where.dataDirectory)
	if err != nil {
		return nil, false, fmt.Errorf("read the durable data of this service: %w", err)
	}
	// The account identifier is what the confinement table is rendered from, and
	// a machine with no such account has none to read. That is not a drift: it is
	// a deployment that has not happened yet, and it is stated as such rather than
	// asked for and turned into a failure.
	identifier := noAccountIdentifier
	if capabilities.AccountPresent {
		identifier, err = executor.AccountIdentifier(where.account)
		if err != nil {
			return nil, false, fmt.Errorf("read the identifier of the service account: %w", err)
		}
	}
	// The confinement of this machine is a table its confined services share, so
	// what a deployment holds itself against is the table that names them all with
	// this one among them — never a table of this profile alone.
	confining, err := confinementJoinedBy(executor, where, identifier)
	if err != nil {
		return nil, false, err
	}
	confinement, err := readEgressBounds(executor, confining)
	if err != nil {
		return nil, false, err
	}

	if present && bytes.Equal(current, desired) && active && image == where.image &&
		dataPresent && confinement.held {
		// The approved state already holds, down to the bytes of the sheet, the
		// identity of the running image, the existence of the data and the bytes of
		// the confinement. Nothing is rewritten and nothing is restarted: a plan
		// that demands what is already true is not an action.
		return privateApplication(subject, where, path, ServiceStateActive, false, nil), false, nil
	}

	// Everything below this line changes the machine, so every failure below it is
	// a controlled failure and not a refusal.
	const touched = true

	if !capabilities.AccountPresent {
		if err := executor.CreateProbeAccount(where.account, where.home, where.comment); err != nil {
			return nil, touched, fmt.Errorf("create the service account: %w", err)
		}
		if err := executor.EnableLinger(where.account); err != nil {
			return nil, touched, fmt.Errorf("enable lingering for the service account: %w", err)
		}
		// Whether that fresh account can really run Podman rootless is a fact about
		// subordinate identifier ranges that cannot be observed before the account
		// exists, so it is re-read rather than assumed. The approved rollback
		// follows, and it removes the service rather than the account.
		refreshed, err := executor.Capabilities(where.account)
		if err != nil {
			return nil, touched, fmt.Errorf("observe the service account after creating it: %w", err)
		}
		if !refreshed.RootlessPodman {
			return nil, touched, fmt.Errorf(
				"the account %s was created but cannot run Podman rootless: this machine now holds that account and no unit",
				where.account,
			)
		}
		identifier, err = executor.AccountIdentifier(where.account)
		if err != nil {
			return nil, touched, fmt.Errorf("read the identifier of the service account: %w", err)
		}
		confining, err = confinementJoinedBy(executor, where, identifier)
		if err != nil {
			return nil, touched, err
		}
	}

	if err := executor.EnsureServiceData(
		where.account, where.durableDirectories(), where.snapshotDirectory); err != nil {
		return nil, touched, fmt.Errorf("prepare the durable data of this service: %w", err)
	}
	if active {
		// The running container was created from a description this machine no
		// longer holds, and it is stopped here rather than after the sheet is
		// written because what comes next lifts its confinement.
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the drifted service: %w", err)
		}
	}
	// The fetch below runs as this service's own account and the table refuses
	// exactly what fetching needs, so this account leaves the table for the length
	// of the fetch. What stays posed meanwhile is every *other* confined account of
	// this machine: no instant of this flow leaves a service somebody else approved
	// running unconfined, and a machine confining this profile alone reaches exactly
	// the lift `#102` proved — a table with nobody left in it is a table removed.
	fetching, err := confinementLeftBy(executor, where)
	if err != nil {
		return nil, touched, err
	}
	if err := settleEgressBounds(executor, confinement, fetching); err != nil {
		return nil, touched, err
	}
	if err := executor.PullImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("fetch the pinned image: %w", err)
	}
	if err := poseEgressBounds(executor, confining); err != nil {
		return nil, touched, err
	}
	if err := executor.WriteUnitFile(path, desired); err != nil {
		return nil, touched, fmt.Errorf("write the Quadlet sheet: %w", err)
	}
	if err := executor.ReloadUserUnits(where.account); err != nil {
		return nil, touched, fmt.Errorf("reload the service account's units: %w", err)
	}
	if err := executor.StartService(where.account, where.serviceName); err != nil {
		return nil, touched, fmt.Errorf("start the service: %w", err)
	}
	if err := executor.ProbeAnswers(subject.localPort, where.expectedContentType); err != nil {
		return nil, touched, fmt.Errorf(
			"the service was started but did not answer on %s:%d: this machine held a started service whose announced state was unproven: %w",
			loopbackAddress, subject.localPort, err,
		)
	}
	return privateApplication(subject, where, path, ServiceStateActive, true, nil), touched, nil
}

// removePrivateService takes the service away and deliberately leaves the data
// where it is.
//
// What a removal takes away is the container, the sheet, the image and the
// confinement — everything that runs. What it keeps is the durable directory and
// every archive beside it, and that is a decision rather than an omission: no
// plan of this product describes the destruction of data, so no operation of this
// package performs one. A human who wants the data gone removes it themselves,
// with their own tools and their own eyes on the path; a human who redeploys
// finds exactly what was there.
//
// That is also what makes the contract's "recréation contrôlée du conteneur"
// nothing more than a removal followed by a deployment: same data, new container,
// two plans a human read.
//
// The presence of the data is therefore *not* part of the decision to act: a
// removal whose service, sheet, image and confinement are already gone changes
// nothing, whether or not the data is still there. Reading it anyway would make
// a machine that kept its data forever unable to say "already removed".
func removePrivateService(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	path := where.unitPath()

	_, present, err := executor.ReadUnitFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read the current Quadlet sheet: %w", err)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}
	image, err := executor.ContainerImage(where.account, where.containerName)
	if err != nil {
		return nil, false, fmt.Errorf("read the running image: %w", err)
	}
	// The confinement this machine is to hold afterwards is the one every other
	// confined account is named in, and it is established before the sheet is taken
	// away — the reading that produces it is a reading of the sheets. A table
	// somebody edited is still rewritten exactly like one this Auxiliary wrote: what
	// is compared is what this machine will hold, not who wrote what it holds.
	remaining, err := confinementLeftBy(executor, where)
	if err != nil {
		return nil, false, err
	}
	confinement, err := readEgressBounds(executor, remaining)
	if err != nil {
		return nil, false, err
	}
	// What survives is read rather than asserted, so that the sentence the report
	// carries is a fact of this machine: these are the archives a removal leaves
	// behind, named, and the reserved slot is not among them.
	kept, err := executor.ServiceArchives(where.snapshotDirectory)
	if err != nil {
		return nil, false, fmt.Errorf("read the archives this machine holds for this service: %w", err)
	}

	if !present && !active && image == "" && confinement.held {
		return privateApplication(subject, where, path, ServiceStateAbsent, false, kept), false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the service: %w", err)
		}
	}
	if present {
		if err := executor.RemoveUnitFile(path); err != nil {
			return nil, touched, fmt.Errorf("remove the Quadlet sheet: %w", err)
		}
		if err := executor.ReloadUserUnits(where.account); err != nil {
			return nil, touched, fmt.Errorf("reload the service account's units: %w", err)
		}
	}
	if err := executor.RemoveImage(where.account, where.image); err != nil {
		return nil, touched, fmt.Errorf("remove the pinned image: %w", err)
	}
	// This account leaves the table last, once nothing of the service is left
	// running. A removal that lifted it first would have an instant holding a
	// running, unconfined service — the very instant the deployment's own order
	// avoids. Where other confined services remain, the table is rewritten without
	// this account rather than taken away: what a removal removes is one service.
	if err := settleEgressBounds(executor, confinement, remaining); err != nil {
		return nil, touched, err
	}
	return privateApplication(subject, where, path, ServiceStateAbsent, true, kept), touched, nil
}

// privateApplication is how a private deployment or removal names what it left
// behind, so that the two say the same things in the same fields.
//
// It names the durable directory in both directions on purpose. After a
// deployment it is where the data lives; after a removal it is what this machine
// still holds — the one line of the report that makes "removing keeps the data,
// redeploying finds it" a statement a reader is given rather than one they have
// to know. The archives a removal keeps are named beside it, by their slots and
// under the same rule as everywhere else: the reserved slot is never among them,
// because it is not a name a human gave. A deployment names none, because it is
// not an operation about archives and a list nobody asked for is noise.
func privateApplication(
	subject instance,
	where placement,
	path, state string,
	changed bool,
	kept []string,
) *Application {
	return &Application{
		Operation:     subject.operation,
		LocalPort:     subject.localPort,
		UnitPath:      path,
		DataPath:      where.dataDirectory,
		SnapshotSlots: kept,
		ServiceState:  state,
		Changed:       changed,
	}
}
