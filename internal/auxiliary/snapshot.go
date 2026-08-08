package auxiliary

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/plan"
)

// This file is the three archive operations of a data-bearing profile: writing a
// named archive, destroying one, and making the data become what one holds.
//
// One value of a plan reaches it: the slot, a label the plan validation has
// already bounded to lower-case letters, digits and hyphens opening on a letter
// or a digit. It carries no separator, cannot be `.` or `..`, and is joined to a
// directory the placement owns — so a slot is always exactly one file inside that
// directory and never a path a document could climb out of.
//
// The reserved slot appears here exactly twice, both times as the constant the
// plan package owns and never as a value read from a document: once as the
// archive a return writes before it replaces anything, and once as the slot a
// return may name because the Controller wrote it into a signed rollback.
//
// One invariant runs through the whole file and is stated once, here: **every
// return writes the data it is about to replace into the reserved slot before it
// replaces anything** — the return of a return included. So no state this machine
// held is ever destroyed by a restore: whatever the data was an instant before,
// it is one approved `restore_service` of the reserved slot away.

// archiveTimeLayout is the one spelling of an instant this product reports. It is
// UTC and RFC 3339, so a digest and the moment it was taken read the same way in
// every report of every machine.
const archiveTimeLayout = time.RFC3339

// requirePlacedService refuses an archive operation aimed at a profile this
// machine holds nothing of, and answers with the loopback port that profile is
// published on.
//
// A snapshot of a stopped service is perfectly ordinary — a private service
// without a route, or with its container down, is a licit steady state and its
// data is exactly what an archive is for. What is refused is a profile that was
// never deployed here: there is no sheet, so this machine has never been told
// what that service is, and archiving a directory nothing describes would be this
// Auxiliary inventing an instance.
//
// The port comes back from that same reading because an archive plan carries
// none, and it must not: a snapshot names a profile and a slot, so the port its
// service answers on is a fact of the sheet this Auxiliary itself wrote, read
// from the machine at the moment it is needed. A sheet no port can be read from
// is refused here, before any effect, rather than discovered after the service
// has been stopped.
func requirePlacedService(executor Executor, where placement) (int, error) {
	sheet, present, err := executor.ReadUnitFile(where.unitPath())
	if err != nil {
		return 0, fmt.Errorf("read the Quadlet sheet of this service: %w", err)
	}
	if !present {
		return 0, fmt.Errorf(
			"this machine holds no %s service: an archive names an instance a plan deployed, so the operation is refused before any effect",
			where.account,
		)
	}
	port, readable := publishedLoopbackPort(sheet)
	if !readable {
		return 0, fmt.Errorf(
			"the sheet of the %s service names no loopback port this machine can read: the operation is refused before any effect",
			where.account,
		)
	}
	return port, nil
}

// publishedLoopbackPort reads the one loopback port a service sheet publishes.
//
// It reads the sheet this Auxiliary wrote rather than a socket that happens to be
// listening, for the reason publishesLoopbackPort does: what may be acted on is a
// managed service described by a plan a human approved, and never whatever
// process got to a port first.
func publishedLoopbackPort(sheet []byte) (int, bool) {
	const published = "PublishPort=" + loopbackAddress + ":"
	for _, line := range strings.Split(string(sheet), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, published) {
			continue
		}
		fields := strings.Split(strings.TrimPrefix(trimmed, published), ":")
		if len(fields) != 2 {
			return 0, false
		}
		port, err := strconv.Atoi(fields[0])
		if err != nil {
			return 0, false
		}
		return port, true
	}
	return 0, false
}

// snapshotService writes the data of one private service into one named slot,
// and reports the digest of what it wrote.
//
// Everything that could refuse happens first and reads only: the service has to
// be one this machine holds, its data has to be there, and the slot has to be
// free. An existing slot is refused rather than replaced, because the backups of
// this product are immutable: reusing a name is a `discard_snapshot` a human
// approves and then a `snapshot_service` they approve after it — two plans, both
// visible. The seam that writes refuses a second time, so the immutability is
// structural as well as checked here.
//
// The service is stopped for the duration and put back exactly as it was found. A
// service that was running is stopped, archived, started again and proven to
// answer; a service that was already stopped is archived and left stopped,
// because the state an archive operation returns a machine to is the state it
// found — not the state a flow would have preferred.
//
// It always reports a change. An archive that was written is a change, and there
// is no second run of the same plan to be idempotent against: the slot now exists
// and refuses the next snapshot naming it.
func snapshotService(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	archivePath := where.archivePath(subject.snapshotSlot)

	port, err := requirePlacedService(executor, where)
	if err != nil {
		return nil, false, err
	}
	dataPresent, err := executor.ServiceDataPresent(where.dataDirectory)
	if err != nil {
		return nil, false, fmt.Errorf("read the durable data of this service: %w", err)
	}
	if !dataPresent {
		return nil, false, fmt.Errorf(
			"this machine holds no data at %s: there is nothing to archive, so the operation is refused before any effect",
			where.dataDirectory,
		)
	}
	taken, err := executor.ServiceArchivePresent(archivePath)
	if err != nil {
		return nil, false, fmt.Errorf("read the archives this machine holds for this service: %w", err)
	}
	if taken {
		return nil, false, fmt.Errorf(
			"the slot %q already holds an archive of this service: backups are immutable, so replacing one is a discard a human approves and a snapshot they approve after it",
			subject.snapshotSlot,
		)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the service before archiving its data: %w", err)
		}
	}
	archive, err := executor.ArchiveServiceData(where.dataDirectory, archivePath)
	if err != nil {
		return nil, touched, fmt.Errorf("archive the data of this service: %w", err)
	}
	if err := restartAndProve(executor, where, active, port); err != nil {
		return nil, touched, err
	}
	application := archiveApplication(subject, where, archive, true)
	if err := namingArchivesHeld(executor, where, application); err != nil {
		return nil, touched, err
	}
	return application, touched, nil
}

// discardSnapshot destroys exactly one named archive, and touches nothing else.
//
// It does not read the service at all, and that is deliberate: an archive is a
// file beside a service, not part of it, so destroying one neither stops nor
// starts anything. An absent slot is not a failure and not a repair — it is the
// approved state, already held.
//
// Its own undoing is a `snapshot_service` of the same slot, which recreates an
// archive of the *current* data rather than of the archive that was destroyed.
// The contract says so in those words, the Console displays it in those words,
// and nothing here pretends otherwise: destroying an archive has no honest
// inverse, and this Auxiliary does not invent one.
func discardSnapshot(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	archivePath := where.archivePath(subject.snapshotSlot)

	present, err := executor.ServiceArchivePresent(archivePath)
	if err != nil {
		return nil, false, fmt.Errorf("read the archives this machine holds for this service: %w", err)
	}
	if !present {
		application := archiveApplication(subject, where, Archive{}, false)
		if err := namingArchivesHeld(executor, where, application); err != nil {
			return nil, false, err
		}
		return application, false, nil
	}

	// Everything below this line changes the machine.
	const touched = true

	if err := executor.RemoveServiceArchive(archivePath); err != nil {
		return nil, touched, fmt.Errorf("remove the archive of this service: %w", err)
	}
	application := archiveApplication(subject, where, Archive{}, true)
	if err := namingArchivesHeld(executor, where, application); err != nil {
		return nil, touched, err
	}
	return application, touched, nil
}

// restoreService makes the data of one private service become what one named slot
// holds.
//
// Everything that could refuse happens first and reads only: the service has to
// be one this machine holds, and the slot has to hold an archive. A slot that
// holds nothing is refused with nothing touched — the reserved one included,
// which is how a return submitted to a machine that never performed a restore is
// refused instead of emptying a service.
//
// Then, in this order and no other:
//
//  1. the service is stopped, if it was running, so nothing writes while the data
//     is being read and replaced;
//  2. the two directories the profile owns are ensured. This is what makes a
//     service whose data has vanished restorable rather than stuck: the reserved
//     slot then honestly records an empty state, which is what was there;
//  3. the exchange: the data becomes what the named slot holds, and the state it
//     replaced is left in the reserved slot. It is one effect and not two, because
//     the two archives may be the same file — see the seam, which reads before it
//     writes. This is the invariant of this file: once it has run, the state this
//     machine was holding an instant ago is recoverable by an approved
//     `restore_service` of the reserved slot, which is exactly the rollback the
//     Controller froze beside this very plan;
//  4. the service is put back exactly as it was found, and proven to answer if it
//     was answering.
//
// A restore naming the reserved slot follows the same steps and swaps the data
// and that slot rather than emptying either: applying it twice returns this
// machine where it started, which is what makes it an honest undoing of itself.
func restoreService(executor Executor, subject instance) (*Application, bool, error) {
	where := subject.placement
	archivePath := where.archivePath(subject.snapshotSlot)
	// The reserved path is built from the plan package's own constant and never
	// from the document: the slot a return writes belongs to the mechanism, and no
	// value that travelled can name it.
	reservedPath := where.archivePath(plan.ReservedSnapshotSlot)

	port, err := requirePlacedService(executor, where)
	if err != nil {
		return nil, false, err
	}
	present, err := executor.ServiceArchivePresent(archivePath)
	if err != nil {
		return nil, false, fmt.Errorf("read the archives this machine holds for this service: %w", err)
	}
	if !present {
		return nil, false, fmt.Errorf(
			"the slot %q holds no archive of this service: there is nothing to return to, so the operation is refused before any effect",
			subject.snapshotSlot,
		)
	}
	active, err := executor.ServiceActive(where.account, where.serviceName)
	if err != nil {
		return nil, false, fmt.Errorf("read the current service state: %w", err)
	}

	// Everything below this line changes the machine.
	const touched = true

	if active {
		if err := executor.StopService(where.account, where.serviceName); err != nil {
			return nil, touched, fmt.Errorf("stop the service before replacing its data: %w", err)
		}
	}
	if err := executor.EnsureServiceData(
		where.account, where.durableDirectories(), where.snapshotDirectory); err != nil {
		return nil, touched, fmt.Errorf("prepare the durable data of this service: %w", err)
	}
	kept, err := executor.ExchangeServiceData(archivePath, where.dataDirectory, reservedPath)
	if err != nil {
		return nil, touched, fmt.Errorf(
			"return the data of this service to the %q slot, keeping the replaced state in %q: %w",
			subject.snapshotSlot, plan.ReservedSnapshotSlot, err)
	}
	if err := restartAndProve(executor, where, active, port); err != nil {
		return nil, touched, err
	}
	// The digest and the instant reported are the reserved slot's, because that is
	// what this operation *wrote*. What it read is named beside them by the slot,
	// and the three together are the whole of what a human needs in order to undo
	// this: the state that was replaced is in the reserved slot, and here is the
	// archive of it.
	application := archiveApplication(subject, where, kept, true)
	application.PreviousSlot = plan.ReservedSnapshotSlot
	if err := namingArchivesHeld(executor, where, application); err != nil {
		return nil, touched, err
	}
	return application, touched, nil
}

// restartAndProve puts a service back exactly as an archive operation found it.
//
// A service that was not running when the operation began is left not running:
// that state was approved by another plan, and an archive operation does not get
// to change it. A service that was running is started again and the same local
// verification a deployment performs is required of it, because a machine that
// stopped a service to touch its data owes the proof that the service came back.
func restartAndProve(executor Executor, where placement, active bool, port int) error {
	if !active {
		return nil
	}
	if err := executor.StartService(where.account, where.serviceName); err != nil {
		return fmt.Errorf("start the service again: %w", err)
	}
	if err := executor.ProbeAnswers(port, where.expectedContentType); err != nil {
		return fmt.Errorf(
			"the service was started again but did not answer on %s:%d: this machine held a started service whose announced state was unproven: %w",
			loopbackAddress, port, err,
		)
	}
	return nil
}

// namingArchivesHeld fills in the archives this machine holds for one profile.
//
// It is read from the directory rather than derived from what the operation just
// did, so that the list is a fact of the machine. The reserved slot is not among
// them and cannot be: the seam that lists them leaves it out, because it is not a
// name a human gave and a human reading this list is reading their own names.
//
// It is what a removal uses as well, over the same directory and for the same
// reason: what a removal keeps is a fact worth stating, not an assurance.
func namingArchivesHeld(executor Executor, where placement, application *Application) error {
	slots, err := executor.ServiceArchives(where.snapshotDirectory)
	if err != nil {
		return fmt.Errorf("read the archives this machine holds for this service: %w", err)
	}
	application.SnapshotSlots = slots
	return nil
}

// archiveApplication is how the three archive operations name what they left
// behind, so that all three say the same things in the same fields.
//
// None of them announces a service state, and the absence is deliberate: the
// vocabulary of this package has two words for a service, running and gone, and
// an archive operation returns a machine to whichever of the two it found. What
// it has to say is about an archive, and it says exactly that.
//
// The digest and the instant are the machine's own conclusions about the archive
// it wrote, and they are the whole of what this product ever says about one. What
// is inside an archive is the data of a vault: no field here, no error of this
// package and no observation can hold a byte of it.
func archiveApplication(subject instance, where placement, archive Archive, changed bool) *Application {
	return &Application{
		Operation:     subject.operation,
		DataPath:      where.dataDirectory,
		SnapshotSlot:  subject.snapshotSlot,
		ArchiveSHA256: archive.SHA256,
		ArchivedAt:    archivedAt(archive),
		Changed:       changed,
	}
}

// archivedAt renders the instant an archive was written, or nothing at all where
// no archive was written: a report says what happened, and a date on nothing is
// not a fact.
func archivedAt(archive Archive) string {
	if archive.TakenAt.IsZero() {
		return ""
	}
	return archive.TakenAt.UTC().Format(archiveTimeLayout)
}
