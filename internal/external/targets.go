package external

import (
	"errors"
	"fmt"

	"github.com/ldesfontaine/your-cloud/internal/machineid"
	"github.com/ldesfontaine/your-cloud/internal/strictjson"
)

// This file is the observation profile of `#107`: the approved selection of
// named information the Daemon may take on explicitly declared targets.
//
// It exists because the Daemon knows only its Relay. The Controller holds the
// declared inventory, the Relay carries no order, and no answer to a Daemon ever
// contains one — so the list of ports a machine may look at cannot come down the
// chain without inventing a downward authority this product refuses to have.
// It comes from the machine instead, root-provisioned beside the anchor of the
// Auxiliary, exactly as the enrolment register does: the machine says what may
// be looked at, the human says what it means, and neither of the two can write
// the other's half.
//
// What the file cannot do is as load-bearing as what it does. It carries no
// address, so nothing can aim a reading off this machine; no label, no kind and
// no identifier, so it can neither name nor rename a declaration; no path, no
// command and no interval, so provisioning it grants nothing beyond being read.

const (
	// TargetsPath is where a machine declares the loopback ports its Daemon may
	// read. An absent file is an answer: this machine looks at nothing.
	TargetsPath = "/etc/your-cloud/external-targets.json"

	// MaxTargetsBytes bounds the file, and MaxTargets bounds what it may name.
	// The second is the envelope's own bound, restated here so that a machine
	// refuses an over-long sheet at the moment it is read rather than producing
	// observations that no longer fit their message.
	MaxTargetsBytes = 4096
	MaxTargets      = 16

	targetsSchema = 1
)

// Targets is the closed document that sheet holds.
type Targets struct {
	SchemaVersion int    `json:"schema_version"`
	MachineID     string `json:"machine_id"`
	ProbePorts    []int  `json:"probe_ports"`
}

// DecodeTargets reads one sheet and refuses everything the contract does not
// allow it to say.
//
// The machine it names must be this one. A sheet copied from another machine
// would make this Daemon report that machine's ports as its own, and the
// Controller keys a reading on the pair of a machine and a port: a viewpoint
// that can be moved by copying a file is not a viewpoint.
func DecodeTargets(data []byte, machineID string) (Targets, error) {
	if err := machineid.Validate(machineID); err != nil {
		return Targets{}, err
	}
	if len(data) == 0 || len(data) > MaxTargetsBytes {
		return Targets{}, fmt.Errorf("external targets must contain 1..%d bytes", MaxTargetsBytes)
	}
	var targets Targets
	if err := strictjson.Decode(data, &targets); err != nil {
		return Targets{}, fmt.Errorf("decode external targets: %w", err)
	}
	if targets.SchemaVersion != targetsSchema {
		return Targets{}, errors.New("unsupported external targets schema_version")
	}
	if targets.MachineID != machineID {
		return Targets{}, errors.New("external targets name another machine")
	}
	if targets.ProbePorts == nil || len(targets.ProbePorts) > MaxTargets {
		return Targets{}, errors.New("external target ports must be a present bounded array")
	}
	previous := 0
	for _, port := range targets.ProbePorts {
		if port < 1 || port > 65535 {
			return Targets{}, errors.New("external target port is outside 1..65535")
		}
		if port <= previous {
			return Targets{}, errors.New("external target ports must be unique and sorted")
		}
		previous = port
	}
	return targets, nil
}
