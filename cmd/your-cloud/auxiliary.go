package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/approval"
	"github.com/ldesfontaine/your-cloud/internal/auxiliary"
)

// The Auxiliary is a one-shot mode of this same binary, never a service, never
// a listener and never a general shell. It reads one bounded document on its
// standard input, verifies it against this machine's own root-owned anchor,
// spends its sequence, and reports what it verified.
//
// It reads exactly one subject, `approve`, and keeps it: the forced SSH command
// and the elevation rule installed at bootstrap authorise that one invocation
// and no free argument, so adding a second subject would mean widening the one
// rule this product allows itself on a managed machine. What changed with the
// first mutating operations is therefore the *input*, not the command line: the
// standard input carries either one signed approval, exactly as before, or one
// closed wrapper carrying that same approval beside the two plan documents its
// digests name. Which of the two was sent is decided by the document itself, and
// a read-only approval still travels alone.
//
// Nothing in this file decides what a mutation does. It verifies the approval,
// hands the documents to internal/auxiliary, and reports what that returned.

type auxiliaryArguments struct {
	anchorPath  string
	stateDir    string
	readerLimit int64
	format      string
}

// auxiliaryReport is what one accepted approval is answered with.
//
// It repeats what was verified rather than what was requested, so a reader
// cannot mistake the Controller's claim for the machine's own conclusion. It
// carries no plan, no secret and no free text: the fields an applied operation
// adds are the closed ones the machine itself decided — where the sheet was
// written, which state the service holds, and whether anything changed.
type auxiliaryReport struct {
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
	ServiceState string `json:"service_state,omitempty"`
	// Outcome names which conclusion this is, in the closed vocabulary of the
	// auxiliary package, so that no reader has to tell a rollback from a refusal
	// by reading a sentence. A read-only diagnostic carries none of these
	// fields, and neither does a refusal: a refusal renders no report at all,
	// which is what keeps it from ever reading as an operation that acted.
	Outcome string `json:"outcome,omitempty"`
	// RollbackAttempted is stated rather than inferred. It is true exactly when
	// this machine was already changed and the approved rollback was run, and
	// Observed is what could still be read after that rollback failed in turn.
	RollbackAttempted bool                   `json:"rollback_attempted,omitempty"`
	Observed          *auxiliary.Observation `json:"observed,omitempty"`
	// Changed is computed by whatever acted, never announced in advance. A
	// read-only diagnostic reports false because it changed nothing; an applied
	// operation reports what it observed before acting and what it did after;
	// and a controlled failure reports true, because a failure that reached the
	// rollback is a failure that had already changed this machine.
	Changed bool `json:"changed"`
}

func runAuxiliary(arguments []string) error {
	configuration, err := parseAuxiliaryArguments(arguments)
	if err != nil {
		return err
	}
	if err := requireAuxiliaryAdministrator(os.Geteuid()); err != nil {
		return err
	}
	document, err := readBoundedInput(os.Stdin, configuration.readerLimit)
	if err != nil {
		return err
	}
	anchor, err := approval.ReadAnchor(configuration.anchorPath)
	if err != nil {
		return err
	}
	input, err := auxiliary.DecodeInput(document)
	if err != nil {
		return err
	}
	now := uint64(time.Now().UTC().Unix())

	// The two subjects of the acceptance are chosen by the shape that was sent,
	// and neither can be reached by an approval meant for the other: an approval
	// arriving alone is verified by the read-only subject, which still refuses
	// every mutation, and an approval arriving with its documents is verified by
	// the mutating one, which refuses every operation that is not one of the two
	// this machine applies.
	if input.Kind == auxiliary.KindDiagnose {
		accepted, err := approval.Accept(configuration.stateDir, anchor, input.Signed, now)
		if err != nil {
			return err
		}
		return renderAuxiliaryReport(os.Stdout, configuration.format, buildAuxiliaryReport(accepted))
	}

	accepted, err := approval.AcceptMutating(configuration.stateDir, anchor, input.Signed, now)
	if err != nil {
		return err
	}
	application, err := auxiliary.Apply(auxiliary.SystemExecutor{}, accepted, input)
	if err != nil {
		// A failure that had already changed this machine is answered like any
		// other conclusion and then still fails: a reader learns what was
		// attempted, what the approved rollback achieved and what this machine
		// was last seen holding, while the exit status stays a failure. A
		// refusal takes neither branch — it changed nothing, so it reports
		// nothing and only says why.
		var controlled *auxiliary.ControlledFailure
		if !errors.As(err, &controlled) {
			return err
		}
		rendered := renderAuxiliaryReport(
			os.Stdout,
			configuration.format,
			buildFailedAuxiliaryReport(accepted, controlled),
		)
		return errors.Join(err, rendered)
	}
	return renderAuxiliaryReport(
		os.Stdout,
		configuration.format,
		buildAppliedAuxiliaryReport(accepted, application),
	)
}

// requireAuxiliaryAdministrator refuses before reading anything: the anchor and
// the anti-replay state are root-owned, and an Auxiliary that could run without
// that authority would be an Auxiliary whose refusals depend on file modes it
// cannot rely on.
func requireAuxiliaryAdministrator(effectiveUserID int) error {
	if effectiveUserID != 0 {
		return errors.New("auxiliary requires local root authority")
	}
	return nil
}

func parseAuxiliaryArguments(arguments []string) (auxiliaryArguments, error) {
	if len(arguments) == 0 || arguments[0] != "approve" {
		return auxiliaryArguments{}, errors.New("auxiliary requires exactly the approve subject")
	}
	result := auxiliaryArguments{
		anchorPath:  approval.AnchorPath,
		stateDir:    approval.StateDirectory,
		readerLimit: auxiliary.MaxInputBytes,
		format:      "text",
	}
	flags := flag.NewFlagSet("auxiliary approve", flag.ContinueOnError)
	flags.StringVar(&result.format, "format", "text", "text or json")
	if err := flags.Parse(arguments[1:]); err != nil {
		return auxiliaryArguments{}, err
	}
	if flags.NArg() != 0 {
		return auxiliaryArguments{}, errorsForUnexpectedArguments("auxiliary approve", flags.Args())
	}
	if result.format != "text" && result.format != "json" {
		return auxiliaryArguments{}, errors.New("auxiliary approve format must be text or json")
	}
	return result, nil
}

// readBoundedInput reads at most one bounded document and refuses anything
// longer instead of truncating it into a shorter, differently signed one.
//
// The bound is the one the whole input may reach. Each document carried inside
// it keeps its own, narrower bound, enforced by the package that owns it, so
// widening this one widened nothing else.
func readBoundedInput(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("auxiliary read limit must be positive")
	}
	document, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read auxiliary input: %w", err)
	}
	if len(document) == 0 || int64(len(document)) > limit {
		return nil, fmt.Errorf("auxiliary input must contain 1..%d bytes", limit)
	}
	return document, nil
}

// buildAuxiliaryReport answers a read-only diagnostic, which changed nothing.
func buildAuxiliaryReport(accepted *approval.Acceptance) auxiliaryReport {
	return auxiliaryReport{
		SchemaVersion:    approval.SchemaVersion,
		Operation:        accepted.Envelope.Operation,
		InfrastructureID: accepted.State.InfrastructureID,
		MachineID:        accepted.State.MachineID,
		ApprovalEpoch:    accepted.State.ApprovalEpoch,
		ConsumedSequence: accepted.State.ConsumedSequence,
		PlanSHA256:       accepted.Envelope.PlanSHA256,
		RollbackSHA256:   accepted.Envelope.RollbackSHA256,
		Privileges:       accepted.Envelope.Privileges,
		Changed:          false,
	}
}

// buildAppliedAuxiliaryReport answers an applied operation with what the machine
// concluded rather than with what the plan asked for.
//
// Everything it adds to the diagnostic report is a closed field decided by the
// application itself: no field of the plan is echoed, and no output of any
// command reaches a reader.
func buildAppliedAuxiliaryReport(accepted *approval.Acceptance, application *auxiliary.Application) auxiliaryReport {
	report := buildAuxiliaryReport(accepted)
	if application == nil {
		return report
	}
	report.PlanOperation = application.Operation
	report.LocalPort = application.LocalPort
	report.UnitPath = application.UnitPath
	report.RouteHost = application.RouteHost
	report.FragmentPath = application.FragmentPath
	report.ServiceState = application.ServiceState
	report.Outcome = auxiliary.OutcomeApplied
	report.Changed = application.Changed
	return report
}

// buildFailedAuxiliaryReport answers a controlled failure.
//
// It names the instance exactly as a success does, states that the approved
// rollback was attempted and says what that attempt reached. It reports no
// service state at all when the rollback failed, because the state of the
// service is precisely what stopped being known: what replaces it is the list of
// what could still be read, and nothing is added to that list to round it off.
func buildFailedAuxiliaryReport(
	accepted *approval.Acceptance,
	failure *auxiliary.ControlledFailure,
) auxiliaryReport {
	report := buildAuxiliaryReport(accepted)
	if failure == nil {
		return report
	}
	report.PlanOperation = failure.Operation
	report.LocalPort = failure.LocalPort
	report.UnitPath = failure.UnitPath
	report.RouteHost = failure.RouteHost
	report.FragmentPath = failure.FragmentPath
	report.Outcome = failure.Outcome
	report.RollbackAttempted = true
	report.Observed = failure.Observed
	report.Changed = true
	return report
}

func renderAuxiliaryReport(writer io.Writer, format string, report auxiliaryReport) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(report)
	}
	if _, err := fmt.Fprintf(writer,
		"operation: %s\ninfrastructure: %s\nmachine: %s\napproval epoch: %d\nconsumed sequence: %d\nplan: %s\nrollback: %s\nprivileges: %v\n",
		report.Operation,
		report.InfrastructureID,
		report.MachineID,
		report.ApprovalEpoch,
		report.ConsumedSequence,
		report.PlanSHA256,
		report.RollbackSHA256,
		report.Privileges,
	); err != nil {
		return err
	}
	// The applied lines exist only when something was applied, so the answer a
	// read-only diagnostic renders stays exactly the one the previous palier
	// proved, line for line.
	if report.PlanOperation != "" {
		if _, err := fmt.Fprintf(writer,
			"plan operation: %s\nlocal port: %d\nunit: %s\noutcome: %s\n",
			report.PlanOperation,
			report.LocalPort,
			report.UnitPath,
			report.Outcome,
		); err != nil {
			return err
		}
	}
	// A route names itself in two lines and in no other. They exist only for the
	// two operations that have a declared name and a fragment, so the answer every
	// previous operation renders stays exactly what it was, line for line.
	if report.RouteHost != "" {
		if _, err := fmt.Fprintf(writer,
			"route: %s\nfragment: %s\n", report.RouteHost, report.FragmentPath,
		); err != nil {
			return err
		}
	}
	// A service state is printed only while there is one to state. A rollback
	// that failed took that certainty away, and the observation below replaces
	// it without pretending to be it.
	if report.ServiceState != "" {
		if _, err := fmt.Fprintf(writer, "service: %s\n", report.ServiceState); err != nil {
			return err
		}
	}
	if report.RollbackAttempted {
		if _, err := fmt.Fprintf(writer, "rollback attempted: true\n"); err != nil {
			return err
		}
	}
	if report.Observed != nil {
		if _, err := fmt.Fprintf(writer,
			"observed account: %s\nobserved unit file: %s\nobserved service: %s\nobserved container: %s\n",
			report.Observed.Account,
			report.Observed.UnitFile,
			report.Observed.Service,
			report.Observed.Container,
		); err != nil {
			return err
		}
		// The fifth word exists only for a route, because it is the only instance
		// whose state is a fragment file. It is absent rather than empty
		// everywhere else, for the same reason it is omitted from the JSON.
		if report.Observed.Fragment != "" {
			if _, err := fmt.Fprintf(writer, "observed fragment: %s\n", report.Observed.Fragment); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(writer, "changed: %t\n", report.Changed)
	return err
}
