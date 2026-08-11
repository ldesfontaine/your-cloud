// Package auxiliaryreport owns the one document a machine renders when an
// approved operation concluded, and the one document the Controller reads back
// off the channel it opened.
//
// It is a package of its own for a reason the contract states plainly: the
// report is written by the Auxiliary and read by the Controller, and a document
// each of them defined separately would be two derivations of the same thing —
// every divergence between them a Controller believing something the machine
// never said. One document, one package, and this package reaches nothing that
// acts: it holds field definitions and no behaviour, so reading a report can
// never become a way to reach what applies one (docs/architecture/TRAJET-DE-COMMANDE.md).
//
// The report carries no plan, no secret and no free text. Its fields are the
// closed ones the machine itself decided.
package auxiliaryreport

// The closed vocabulary of conclusions a mutating operation may reach, owned
// here beside the document that carries them.
const (
	// OutcomeApplied is the machine holding the approved state, whether reaching
	// it changed anything or found it already true.
	OutcomeApplied = "applied"
	// OutcomeRolledBack is a controlled failure whose approved rollback was
	// attempted and reached the state that rollback describes.
	OutcomeRolledBack = "rolled_back_after_controlled_failure"
	// OutcomePartial is a controlled failure whose approved rollback was
	// attempted and failed in its turn. It claims nothing about the machine
	// beyond what a read could still establish.
	OutcomePartial = "partial_state_after_failed_rollback"
)

// Report is what one accepted approval is answered with.
//
// It repeats what was verified rather than what was requested, so a reader
// cannot mistake the Controller's claim for the machine's own conclusion. It
// carries no plan, no secret and no free text: the fields an applied operation
// adds are the closed ones the machine itself decided — where the sheet was
// written, which state the service holds, and whether anything changed.
type Report struct {
	SchemaVersion    int      `json:"schema_version"`
	Operation        string   `json:"operation"`
	InfrastructureID string   `json:"infrastructure_id"`
	MachineID        string   `json:"machine_id"`
	ApprovalEpoch    uint64   `json:"approval_epoch"`
	ConsumedSequence uint64   `json:"consumed_sequence"`
	PlanSHA256       string   `json:"plan_sha256"`
	RollbackSHA256   string   `json:"rollback_sha256"`
	Privileges       []string `json:"privileges"`
	// PlanOperation is the operation the two verified documents describe. It is
	// reported beside the envelope's own operation because the machine refuses
	// to act unless the two say the same thing, and a reader is entitled to see
	// both rather than to trust that they were compared.
	PlanOperation string `json:"plan_operation,omitempty"`
	LocalPort     int    `json:"local_port,omitempty"`
	UnitPath      string `json:"unit_path,omitempty"`
	// RouteHost and FragmentPath name a published route, and are the only two
	// fields the entrypoint and route operations added to this answer. They name
	// the declared host and the one file that host owns on this machine; the
	// certificate and the key of that host are read from a directory this
	// Auxiliary never writes, and neither their paths nor their contents travel
	// back here. A report of this product carries what the machine concluded, and
	// a key is not a conclusion.
	RouteHost    string `json:"route_host,omitempty"`
	FragmentPath string `json:"fragment_path,omitempty"`
	// PassageState is filled by the two operations of a route the private passage
	// carries, and says whether the junction that carries the published name was
	// there when this machine acted.
	//
	// It exists because the failure of the passage must never be silent: a
	// publication reports it active, since it refuses otherwise, and a retirement
	// reports what it found — so a human retiring a name on a machine whose tunnel
	// has fallen reads that fact here instead of inferring it from a name that had
	// stopped answering. Nothing repairs it: the reprise is a junction a human
	// approves.
	PassageState string `json:"passage_state,omitempty"`
	// LinkPublicKey is the public half of the passage key the machine that
	// prepared its own side of the private passage holds. It is the one value of
	// that palier that is meant to travel: the Controller reads it here as an
	// observation and carries it, readable, into the junction plan of the other
	// machine, so the human who approves that plan names exactly the peer they
	// accept.
	//
	// No other operation fills it, and no operation of this product fills
	// anything with the private half. A private key is born on its machine and
	// never leaves it, so there is nothing here that could carry one — not in a
	// success, not in a controlled failure, and not in an observation, which
	// reports a key present or absent and never by its value.
	LinkPublicKey string `json:"link_public_key,omitempty"`
	// DataPath, SnapshotSlot, PreviousSlot, ArchiveSHA256, ArchivedAt and
	// SnapshotSlots are what the operations of a data-bearing profile added to this
	// answer, and every one of them is a conclusion of the machine rather than a
	// field of a plan echoed back.
	//
	// DataPath names the durable directory: after a deployment it is where the data
	// lives, and after a removal it is what this machine still holds — a removal of
	// this product takes the service away and keeps the data, so the report says so
	// rather than leaving a reader to assume either way. SnapshotSlot names the
	// archive that was acted on and PreviousSlot the reserved slot a return wrote
	// the replaced state into, so the document that undoes a return is readable in
	// the report of the return itself. ArchiveSHA256 and ArchivedAt are the digest
	// of the archive and the instant it was written.
	//
	// SnapshotSlots are the archives this machine holds afterwards, by the names a
	// human gave them; the reserved slot is never among them. What is *inside* an
	// archive never appears here and cannot: the data of a vault is not a
	// conclusion, and no field of this report, of an error or of an observation can
	// hold a byte of it.
	DataPath string `json:"data_path,omitempty"`
	// SecretsPath is the directory holding the values this machine generated for a
	// user service, and it is filled by the two operations of that door alone.
	//
	// It names a directory and never a value: a generated value is born on this
	// machine, stays on it and enters no document, no report and no observation. A
	// removal fills it for the reason it fills DataPath — a removal of this product
	// keeps the data, the archives and the secrets, so the report says which
	// directories survive rather than leaving a reader to assume either way.
	SecretsPath   string   `json:"secrets_path,omitempty"`
	SnapshotSlot  string   `json:"snapshot_slot,omitempty"`
	PreviousSlot  string   `json:"previous_slot,omitempty"`
	ArchiveSHA256 string   `json:"archive_sha256,omitempty"`
	ArchivedAt    string   `json:"archived_at,omitempty"`
	SnapshotSlots []string `json:"snapshot_slots,omitempty"`
	ServiceState  string   `json:"service_state,omitempty"`
	// Outcome names which conclusion this is, in the closed vocabulary of the
	// auxiliary package, so that no reader has to tell a rollback from a refusal
	// by reading a sentence. A read-only diagnostic carries none of these
	// fields, and neither does a refusal: a refusal renders no report at all,
	// which is what keeps it from ever reading as an operation that acted.
	Outcome string `json:"outcome,omitempty"`
	// RollbackAttempted is stated rather than inferred. It is true exactly when
	// this machine was already changed and the approved rollback was run, and
	// Observed is what could still be read after that rollback failed in turn.
	RollbackAttempted bool         `json:"rollback_attempted,omitempty"`
	Observed          *Observation `json:"observed,omitempty"`
	// Changed is computed by whatever acted, never announced in advance. A
	// read-only diagnostic reports false because it changed nothing; an applied
	// operation reports what it observed before acting and what it did after;
	// and a controlled failure reports true, because a failure that reached the
	// rollback is a failure that had already changed this machine.
	Changed bool `json:"changed"`
}

// Observation is what read-only calls could still establish about this machine
// after a rollback had itself failed.
//
// It is written in the closed vocabulary above and never in the words of a
// command: a reader learns what was seen, or that it could not be seen at all.
// It is deliberately incapable of saying that the machine is in a known state,
// because a failed rollback is precisely the moment that ceased to be true.
// Which words it carries is decided by the kind of instance that was being
// applied, and every one of them is omitted rather than reported empty where the
// operation never touched what it answers for: an observation says what was
// seen, and a word about something nobody looked at would be neither a fact nor
// an admission. The four words of an account and a container are what a service,
// an entrypoint and a route are left holding; a route adds the one file it is;
// and a passage carries none of the four, because it has neither an account nor
// a container to be left holding.
type Observation struct {
	Account   string `json:"account,omitempty"`
	UnitFile  string `json:"unit_file,omitempty"`
	Service   string `json:"service,omitempty"`
	Container string `json:"container,omitempty"`
	// Fragment is filled only while the instance that was being applied is a
	// route of either kind, because it is the only instance whose state is a
	// fragment file. For a route the passage carries it may also read `unbacked`,
	// which is the fragment being there and the junction not — the one state this
	// palier's contract asks to be observable rather than inferred.
	Fragment string `json:"fragment,omitempty"`
	// LinkKey, LinkInterface, LinkPeer and LinkBounds are filled only for a
	// passage. The key is reported present or absent and never by its value: the
	// public half would say more than an observation needs, and the private half
	// is not something any function of this package can reach. The bounds are
	// reported the same way and for the reason the peer is: after a rollback that
	// failed in its turn, whether this machine is left holding a peer nothing
	// bounds — or bounds with nothing left to bound — is exactly what a human has
	// to read, and neither can be inferred from the other.
	LinkKey       string `json:"link_key,omitempty"`
	LinkInterface string `json:"link_interface,omitempty"`
	LinkPeer      string `json:"link_peer,omitempty"`
	LinkBounds    string `json:"link_bounds,omitempty"`
	// Data, Egress and Archive are filled only for the operations of a
	// data-bearing profile, and they are three words rather than one because
	// neither can be inferred from the others. After a rollback that failed in its
	// turn, whether this machine still holds the data, whether the account is still
	// confined, and whether the archive the operation was writing exists are
	// exactly the three things a human has to read. Each is reported present or
	// absent and never by its content: an archive is named, never opened.
	Data    string `json:"data,omitempty"`
	Egress  string `json:"egress,omitempty"`
	Archive string `json:"archive,omitempty"`
}
