package external

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/securefile"
)

// This is the one file of the package that touches the machine, and everything
// it binds is a read.
//
// The loopback address is a constant here rather than a value anybody passes,
// which is what makes "the adapter never reaches the network" a property of the
// program instead of a check somebody remembered to write: there is no code path
// in this package that can produce any other address.

const (
	// LoopbackAddress is the only address this package ever dials. A declaration
	// carries a port and never a host, and an element that lives somewhere else is
	// not verifiable by this palier — which the App says rather than guesses.
	LoopbackAddress = "127.0.0.1"

	// dialTimeout bounds waiting for something to accept, and readTimeout bounds
	// waiting for it to talk. Both are short: this runs inside the Daemon's own
	// collection cadence, and a reading that could hang would be a collection that
	// stops happening.
	dialTimeout = 2 * time.Second
	readTimeout = 2 * time.Second
)

// SystemSight binds the two reads to this machine, and binds nothing else.
func SystemSight() Sight {
	return Sight{Open: systemOpen, ReadFile: systemReadFile}
}

// systemOpen makes one bounded connection to one loopback port and hands back
// the bytes it may yield.
//
// The deadline is set on the connection before it is returned, so the bound
// applies to whoever reads it and cannot be forgotten by the caller. What comes
// back is an io.ReadCloser rather than the connection: the caller receives Read
// and Close, and no way to send anything at all.
func systemOpen(ctx context.Context, port int) (io.ReadCloser, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("probe_port is outside 1..65535")
	}
	dialer := net.Dialer{Timeout: dialTimeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(LoopbackAddress, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if err := connection.SetDeadline(time.Now().Add(readTimeout)); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

// systemReadFile reads the three files this collection needs, and refuses every
// other path by name.
//
// The declared sheet is read with the discipline every root-provisioned
// authority file of this product is read with — canonical path, real root-owned
// directory, no final symbolic link, bounded size. The kernel's own socket
// tables and the account table are read plainly, because they are neither
// authorities of this product nor files it provisions, and because /proc/net is
// itself a link the safe reader is right to refuse.
func systemReadFile(path string) ([]byte, error) {
	switch path {
	case TargetsPath:
		return securefile.ReadRootOwned(path, MaxTargetsBytes)
	case tcpTablePath, tcp6TablePath, accountTablePath:
		return os.ReadFile(path)
	default:
		return nil, errors.New("this reading opens no path of its own")
	}
}
