package external

import (
	"context"
	"errors"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

// The four outcomes this package concludes are the envelope's own, bound here at
// compile time rather than spelled twice: a vocabulary that can drift between
// the reader and the wire is a vocabulary somebody will read differently at each
// end.
const (
	outcomeAnswered   = observation.ExternalAnswered
	outcomeNoListener = observation.ExternalNoListener
	outcomeTooLarge   = observation.ExternalTooLarge
	outcomeManaged    = observation.ExternalManaged
)

// Sight is everything this package is given of the machine it runs on, and it is
// deliberately two functions that return bytes.
//
// One yields the answer of a loopback port, the other the content of a file.
// Neither of them can create, replace, remove, execute or elevate anything, and
// there is no third: the collection below has no way to change the machine it
// reads, whatever it concludes.
type Sight struct {
	Open     Open
	ReadFile func(string) ([]byte, error)
}

// Collect takes one reading of every port this machine's own sheet declares.
//
// The order of the two questions is the argument. Who holds the socket is asked
// first, and a port this product itself published is reported as such without
// ever being connected to: the reading that would have followed could only have
// said "something answered", which is exactly the sentence that would have let a
// managed service be presented as an external one.
//
// A machine with no sheet reports nothing at all, and a sheet that cannot be
// read or cannot be trusted makes this machine report nothing rather than report
// a guess. Nothing here fails the collection of the host's own health: an
// external reading that could not be taken is an absence the Controller ages
// honestly, and it is never a reason to stop observing a machine.
func Collect(ctx context.Context, sight Sight, machineID string) ([]observation.ExternalReading, error) {
	if sight.Open == nil || sight.ReadFile == nil {
		return nil, errors.New("an external collection requires its two bounded reads")
	}
	sheet, err := sight.ReadFile(TargetsPath)
	if err != nil {
		return nil, nil
	}
	targets, err := DecodeTargets(sheet, machineID)
	if err != nil {
		return nil, err
	}
	if len(targets.ProbePorts) == 0 {
		return nil, nil
	}
	managed, err := productPorts(sight.ReadFile)
	if err != nil {
		return nil, err
	}
	adapter, err := NewAdapter(sight.Open)
	if err != nil {
		return nil, err
	}
	readings := make([]observation.ExternalReading, 0, len(targets.ProbePorts))
	for _, port := range targets.ProbePorts {
		if _, held := managed[port]; held {
			readings = append(readings, observation.ExternalReading{ProbePort: port, Outcome: outcomeManaged})
			continue
		}
		outcome, err := adapter.Read(ctx, port)
		if err != nil {
			return nil, err
		}
		readings = append(readings, observation.ExternalReading{ProbePort: port, Outcome: outcome})
	}
	return readings, nil
}
