package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/ldesfontaine/your-cloud/internal/relay"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.New(os.Stderr, "your-cloud: ", 0).Print(err)
		os.Exit(2)
	}
}

// run selects one role without merging their process, configuration or
// lifecycle boundaries. Production always uses the fixed candidate path.
func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("a role is required: daemon or relay")
	}
	switch arguments[0] {
	case "daemon":
		return runDaemon(arguments[1:])
	case "relay":
		return runRelay(arguments[1:], relay.CandidateManifestPath)
	default:
		return fmt.Errorf("unknown role %q: expected daemon or relay", arguments[0])
	}
}

func errorsForUnexpectedArguments(role string, arguments []string) error {
	return fmt.Errorf("%s accepts no positional arguments: %q", role, arguments)
}
