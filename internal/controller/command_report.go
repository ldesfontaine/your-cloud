package controller

import (
	"errors"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/auxiliaryreport"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// Reading what the machine answered (docs/architecture/TRAJET-DE-COMMANDE.md,
// maillon 5).
//
// The report comes back on the standard output of the channel this Controller
// opened, so there is no new inbound route and no new listener on any machine.
// What was missing was never a way back — it was somebody to read the one that
// already existed.
//
// **The document is not redefined here.** It lives in `internal/auxiliaryreport`
// with the machine that writes it: a report each side defined separately would
// be two derivations of the same thing, and every divergence between them would
// be this Controller believing something the machine never said.
//
// **Ingestion refuses everything that does not name this dispatch.** A report is
// evidence about one launch, and a document that describes another launch — or
// another machine, or another position — is not weaker evidence about this one,
// it is evidence about something else. It is discarded, and the dispatch stays
// `lancé, non rapporté` rather than becoming a success nobody established.

// maxCommandReportBytes bounds a report before it is parsed. It is the bound
// the machine's own standard input already carries for the documents it
// answers about, and a report says less than what it answers about: bounding
// the reader here means a machine that talks forever cannot make this
// Controller grow, whatever the machine believes about its own limits.
const maxCommandReportBytes = 64 * 1024

// reportMismatchError names why a report was discarded, in the closed
// vocabulary of the contract's table. It never carries a fragment of the
// document: a reason is a reason, not an echo.
type reportMismatchError struct{ reason string }

func (err *reportMismatchError) Error() string { return err.reason }

// ingestReport holds one answer against the dispatch it claims to conclude and
// returns what the record may record from it.
//
// The order is the contract's table, and every branch of it discards rather
// than weakens: there is no partial acceptance of a report, because a report
// that got one of these five wrong is not a report about this launch.
func ingestReport(record DispatchRecord, infrastructureID string, answer []byte) (auxiliaryreport.Report, error) {
	if len(answer) == 0 {
		return auxiliaryreport.Report{}, &reportMismatchError{"the machine rendered no report"}
	}
	if len(answer) > maxCommandReportBytes {
		return auxiliaryreport.Report{}, &reportMismatchError{"the answer is past the bound a report may reach"}
	}
	var report auxiliaryreport.Report
	if err := strictjson.Decode(answer, &report); err != nil {
		return auxiliaryreport.Report{}, &reportMismatchError{"the answer is not a report this Controller reads"}
	}
	switch {
	case report.InfrastructureID != infrastructureID || report.MachineID != record.MachineID:
		return auxiliaryreport.Report{}, &reportMismatchError{
			"the report names another infrastructure or another machine than this dispatch"}
	case report.Operation != record.Operation:
		return auxiliaryreport.Report{}, &reportMismatchError{
			"the report names another operation than the envelope"}
	case report.ApprovalEpoch != record.ApprovalEpoch || report.ConsumedSequence != record.Sequence:
		return auxiliaryreport.Report{}, &reportMismatchError{
			"the report names another position than the envelope"}
	case report.PlanSHA256 != record.PlanSHA256 || report.RollbackSHA256 != record.RollbackSHA256:
		return auxiliaryreport.Report{}, &reportMismatchError{
			"the report names another pair than the one the approval signs"}
	}
	return report, nil
}

// reportedConclusion turns an accepted report into the two fields a record
// keeps from it. Everything else the report carries belongs to the machine's
// own account and is not this Controller's to store: the registry holds what a
// dispatch concluded, never a copy of a document.
func reportedConclusion(report auxiliaryreport.Report) (changed bool, outcome string, err error) {
	if report.Outcome == "" {
		// A read-only diagnostic concludes without naming an outcome, and that
		// is the one honest gap: the record says so rather than inventing a
		// word the machine did not write.
		return report.Changed, "", nil
	}
	switch report.Outcome {
	case auxiliaryreport.OutcomeApplied,
		auxiliaryreport.OutcomeRolledBack,
		auxiliaryreport.OutcomePartial:
		return report.Changed, report.Outcome, nil
	default:
		return false, "", fmt.Errorf("the report names the unknown outcome %q", report.Outcome)
	}
}

// discardedReport tells the caller a report was read and refused, so that the
// conclusion can stay honest without the reason ever being mistaken for the
// machine's own sentence.
func discardedReport(err error) bool {
	var mismatch *reportMismatchError
	return errors.As(err, &mismatch)
}
