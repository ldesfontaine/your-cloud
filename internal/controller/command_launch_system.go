package controller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
)

// systemCommandRunner is the real effect of the launch on a real machine, kept
// apart from the decisions of `command_launch.go` so that everything which
// decides can be read and tested without a process ever being created.
//
// It answers one question the exit code cannot: were the wrapper's bytes
// written before the failure? That is the observation `non lancé` rests on, and
// it is taken from the write itself rather than guessed from a client's
// diagnostics — reading OpenSSH's own sentences to classify a failure would be
// the coupling to a presentation this product refuses everywhere else.
type systemCommandRunner struct {
	// maxAnswerBytes bounds each of the two channels read back. The report is
	// bounded by the package that owns it and the sentence by the registry;
	// this is the reader's own ceiling, so a machine that talks forever cannot
	// make this Controller grow.
	maxAnswerBytes int64
}

func (runner systemCommandRunner) Run(
	ctx context.Context, program string, arguments []string, standardInput []byte,
) commandResult {
	command := exec.CommandContext(ctx, program, arguments...)
	// No environment at all. The client must read its identity, its known
	// hosts and its options from the arguments above and from nowhere else,
	// and an inherited environment is a place a variable could speak.
	command.Env = []string{}
	var answer, diagnostics bytes.Buffer
	command.Stdout = &answer
	command.Stderr = &diagnostics
	input, err := command.StdinPipe()
	if err != nil {
		return commandResult{Err: err}
	}
	if err := command.Start(); err != nil {
		return commandResult{Err: err}
	}

	// The wrapper is written whole or not at all, and what happened is
	// recorded before anything is concluded from it.
	written, writeErr := input.Write(standardInput)
	closeErr := input.Close()
	wrote := writeErr == nil && written == len(standardInput)

	waitErr := command.Wait()
	result := commandResult{
		StandardOutput:     boundedAnswer(&answer, runner.maxAnswerBytes),
		StandardError:      boundedAnswer(&diagnostics, runner.maxAnswerBytes),
		WroteStandardInput: wrote,
	}
	var exited *exec.ExitError
	switch {
	case waitErr == nil:
		result.ExitCode = 0
	case errors.As(waitErr, &exited):
		result.ExitCode = exited.ExitCode()
	default:
		// The client could not be run or was cut down: this Controller's own
		// failure, never the machine's answer.
		result.Err = waitErr
	}
	if wrote && closeErr != nil && result.Err == nil {
		result.Err = closeErr
	}
	return result
}

func boundedAnswer(buffer *bytes.Buffer, maximum int64) []byte {
	data, _ := io.ReadAll(io.LimitReader(buffer, maximum))
	return data
}
