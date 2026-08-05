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
)

// The Auxiliary is a one-shot mode of this same binary, never a service, never
// a listener and never a general shell. It reads one signed approval on its
// standard input, verifies it against this machine's own root-owned anchor,
// spends its sequence, and reports what it verified.
//
// It performs a protocol diagnostic and nothing else. There is no path through
// this file that installs, enables, configures, writes or removes anything on
// the machine, and `changed` is a constant below rather than a computed value:
// this palier has no mutation to report.

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
// carries no plan, no secret and no output of any command.
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
	// Changed is always false in this palier. It is reported rather than
	// omitted so that a future first real mutation has to change this value
	// explicitly, and so no success here can be read as an OCI action.
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
	document, err := readBoundedApproval(os.Stdin, configuration.readerLimit)
	if err != nil {
		return err
	}
	anchor, err := approval.ReadAnchor(configuration.anchorPath)
	if err != nil {
		return err
	}
	signed, err := approval.DecodeSigned(document)
	if err != nil {
		return err
	}
	accepted, err := approval.Accept(
		configuration.stateDir,
		anchor,
		signed,
		uint64(time.Now().UTC().Unix()),
	)
	if err != nil {
		return err
	}
	return renderAuxiliaryReport(os.Stdout, configuration.format, buildAuxiliaryReport(accepted))
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
		readerLimit: approval.MaxSignedApprovalBytes,
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

// readBoundedApproval reads at most one bounded document and refuses anything
// longer instead of truncating it into a shorter, differently signed one.
func readBoundedApproval(reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("approval read limit must be positive")
	}
	document, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read signed approval: %w", err)
	}
	if len(document) == 0 || int64(len(document)) > limit {
		return nil, fmt.Errorf("signed approval must contain 1..%d bytes", limit)
	}
	return document, nil
}

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

func renderAuxiliaryReport(writer io.Writer, format string, report auxiliaryReport) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(report)
	}
	_, err := fmt.Fprintf(writer,
		"operation: %s\ninfrastructure: %s\nmachine: %s\napproval epoch: %d\nconsumed sequence: %d\nplan: %s\nrollback: %s\nprivileges: %v\nchanged: %t\n",
		report.Operation,
		report.InfrastructureID,
		report.MachineID,
		report.ApprovalEpoch,
		report.ConsumedSequence,
		report.PlanSHA256,
		report.RollbackSHA256,
		report.Privileges,
		report.Changed,
	)
	return err
}
