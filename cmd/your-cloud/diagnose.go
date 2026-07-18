package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/buffer"
	"github.com/ldesfontaine/your-cloud/internal/daemon"
	"github.com/ldesfontaine/your-cloud/internal/observation"
	"github.com/ldesfontaine/your-cloud/internal/securefile"
)

const daemonPublicCertificatePath = "/etc/your-cloud/daemon.crt"

type diagnosticArguments struct {
	format string
}

type observationDiagnostic struct {
	MachineID          string       `json:"machine_id"`
	DaemonVersion      string       `json:"daemon_version"`
	Profile            string       `json:"profile"`
	RelayEndpoint      string       `json:"relay_endpoint"`
	CertificateExpires string       `json:"certificate_expires_at"`
	LastCollected      string       `json:"last_collected_at,omitempty"`
	Stats              buffer.Stats `json:"buffer"`
}

func runDiagnose(arguments []string) error {
	configuration, err := parseDiagnosticArguments(arguments)
	if err != nil {
		return err
	}
	if err := requireDiagnosticAdministrator(os.Geteuid()); err != nil {
		return err
	}
	inspection, err := buffer.Inspect(daemonStateDirectory, buffer.DefaultLimits())
	if err != nil {
		return fmt.Errorf("diagnose observation buffer: %w", err)
	}
	certificatePEM, err := securefile.ReadRootOwned(daemonPublicCertificatePath, 32*1024)
	if err != nil {
		return fmt.Errorf("diagnose observation certificate: %w", err)
	}
	certificate, err := parsePublicCertificate(certificatePEM)
	if err != nil {
		return err
	}
	diagnostic, err := buildObservationDiagnostic(inspection, certificate)
	if err != nil {
		return err
	}
	return renderObservationDiagnostic(os.Stdout, configuration.format, diagnostic)
}

func requireDiagnosticAdministrator(effectiveUserID int) error {
	if effectiveUserID != 0 {
		return errors.New("diagnose observation requires local root authority")
	}
	return nil
}

func parseDiagnosticArguments(arguments []string) (diagnosticArguments, error) {
	if len(arguments) == 0 || arguments[0] != "observation" {
		return diagnosticArguments{}, errors.New("diagnose requires exactly the observation subject")
	}
	var result diagnosticArguments
	flags := flag.NewFlagSet("diagnose observation", flag.ContinueOnError)
	flags.StringVar(&result.format, "format", "text", "text or json")
	if err := flags.Parse(arguments[1:]); err != nil {
		return diagnosticArguments{}, err
	}
	if flags.NArg() != 0 {
		return diagnosticArguments{}, errorsForUnexpectedArguments("diagnose observation", flags.Args())
	}
	if result.format != "text" && result.format != "json" {
		return diagnosticArguments{}, errors.New("diagnose observation format must be text or json")
	}
	return result, nil
}

func parsePublicCertificate(encoded []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("daemon public certificate must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse daemon public certificate: %w", err)
	}
	return certificate, nil
}

func buildObservationDiagnostic(inspection buffer.Inspection, certificate *x509.Certificate) (observationDiagnostic, error) {
	if inspection.Current == nil {
		return observationDiagnostic{}, errors.New("no local observation has been collected")
	}
	current := inspection.Current
	if current.Profile != observation.Profile || current.DaemonVersion != observation.DaemonVersion {
		return observationDiagnostic{}, errors.New("local observation does not match v0.0.2")
	}
	return observationDiagnostic{
		MachineID:          current.MachineID,
		DaemonVersion:      current.DaemonVersion,
		Profile:            current.Profile,
		RelayEndpoint:      daemon.ApprovedRelayOrigin,
		CertificateExpires: certificate.NotAfter.UTC().Format(time.RFC3339Nano),
		LastCollected:      current.ObservedAt,
		Stats:              inspection.Stats,
	}, nil
}

func renderObservationDiagnostic(writer io.Writer, format string, diagnostic observationDiagnostic) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(diagnostic)
	}
	_, err := fmt.Fprintf(writer,
		"machine: %s\nversion: %s\nprofile: %s\nrelay: %s\ncertificate expires: %s\nlast collected: %s\nlast delivered: %s\ndelivery: %s\npending: %d records / %d bytes\noldest pending: %s\nnext sequence: %d\ngaps: %d\n",
		diagnostic.MachineID,
		diagnostic.DaemonVersion,
		diagnostic.Profile,
		diagnostic.RelayEndpoint,
		diagnostic.CertificateExpires,
		diagnostic.LastCollected,
		diagnostic.Stats.LastDelivered,
		diagnostic.Stats.DeliveryState,
		diagnostic.Stats.PendingRecords,
		diagnostic.Stats.PendingBytes,
		diagnostic.Stats.OldestObserved,
		diagnostic.Stats.NextSequence,
		diagnostic.Stats.GapCount,
	)
	return err
}
