package external

import (
	"context"
	"errors"
	"io"
)

// This file is the adapter of `#107`, and it is the whole of it.
//
// Its inability to write is not a rule a reviewer applies: it is the shape of
// what it is given. An Adapter holds exactly one value, a function that takes a
// port number and yields an io.ReadCloser. There is no address to aim, no
// filesystem, no command, no engine, no effects seam and no store — a code that
// is not given the means to write cannot write. The interface it receives back
// carries Read and Close and nothing else, so this file cannot even send a byte
// to the thing it is reading: what it proves is that something accepted a
// connection, which is precisely what the contract lets it claim.
//
// The imports above are the second half of the same argument, and a test holds
// them to exactly this list.

const (
	// maxResponseBytes is how far the answer of a third party is read before the
	// reading gives up on concluding. A few kilobytes is what the contract allows,
	// and what is read is counted and discarded — never parsed, never stored,
	// never rendered.
	maxResponseBytes = 4096
)

// Open is the one seam of this package that touches anything outside it.
//
// It takes a port and returns bytes. It does not take a host, a scheme, a path
// or a header, because none of those is a choice this palier gives anybody: the
// read is made on the enrolled machine's own loopback, and the address is a
// constant of the binding rather than a value that travels.
type Open func(ctx context.Context, port int) (io.ReadCloser, error)

// Adapter reads declared loopback ports and concludes nothing else.
type Adapter struct {
	open Open
}

// NewAdapter refuses an adapter with no way to read, rather than one that
// silently concludes that nothing is listening anywhere.
func NewAdapter(open Open) (*Adapter, error) {
	if open == nil {
		return nil, errors.New("a read-only adapter requires its bounded read")
	}
	return &Adapter{open: open}, nil
}

// Read takes one bounded reading of one loopback port and names what happened.
//
// The four conclusions are facts about a connection:
//
//   - ExternalAnswered — something accepted a connection on this port. Whether
//     it volunteered bytes, and which bytes, changes nothing: no profile of this
//     palier describes a content, so nothing here may claim one;
//   - ExternalNoListener — nothing accepted a connection;
//   - ExternalTooLarge — something accepted and was still talking at the bound.
//     The reading is cut rather than followed, and a reading that had to be cut
//     is reported as such instead of being called a success.
//
// The fourth, ExternalManaged, is not decided here: it is a fact about who holds
// the socket rather than about what the socket did, and it is constated in
// owner.go before this is ever called.
//
// The bytes are read into io.Discard. They are inert: not code, not markup, not
// an instruction, and never a value this function returns.
func (adapter *Adapter) Read(ctx context.Context, port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", errors.New("probe_port is outside 1..65535")
	}
	stream, err := adapter.open(ctx, port)
	if err != nil {
		return outcomeNoListener, nil
	}
	defer stream.Close()
	read, _ := io.Copy(io.Discard, io.LimitReader(stream, maxResponseBytes+1))
	if read > maxResponseBytes {
		return outcomeTooLarge, nil
	}
	return outcomeAnswered, nil
}
