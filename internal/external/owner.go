package external

import (
	"errors"
	"strconv"
	"strings"
)

// This file answers the one question `#106` could not: whether a port a human
// declared external is in fact a port this product itself published.
//
// The contract left that refusal to the machine, because the Controller knows
// the machines and not their sheets. What the machine can be asked, without a
// privilege and without a guess, is who holds the listening socket right now:
// the kernel writes it down, and the account table says whose identifier that
// is. An account of this product carries the product's own prefix — the sheets
// say so in as many words, and the prefix exists precisely so that a role-shaped
// name never silently adopts a generic system group.
//
// The answer is a constat and not a comparison against a record: nothing here
// reads a plan, an inventory or a sheet of the Auxiliary, and nothing here can
// be talked into believing a port is free.

const (
	// tcpTablePath and tcp6TablePath are the kernel's own tables of sockets. Both
	// are read because a service may listen on either family and a port held over
	// one of them is held.
	tcpTablePath  = "/proc/net/tcp"
	tcp6TablePath = "/proc/net/tcp6"

	// accountTablePath is where this machine says which identifier is which
	// account, and productAccountPrefix is what an account of this product is
	// named with.
	accountTablePath      = "/etc/passwd"
	productAccountPrefix  = "your-cloud-"
	listeningSocketState  = "0A"
	maxSocketTableEntries = 65536
)

// productPorts reports the ports this machine currently holds under an account
// of this product.
//
// A table that cannot be read is an error and never a quiet empty set: a machine
// that cannot be asked has not answered, and answering "no managed port" would
// be exactly the silent presentation this refusal exists to prevent.
func productPorts(readFile func(string) ([]byte, error)) (map[int]struct{}, error) {
	if readFile == nil {
		return nil, errors.New("reading the machine's own tables requires its read seam")
	}
	accounts, err := readFile(accountTablePath)
	if err != nil {
		return nil, err
	}
	product := productIdentifiers(accounts)
	ports := make(map[int]struct{})
	answered := false
	for _, path := range []string{tcpTablePath, tcp6TablePath} {
		table, err := readFile(path)
		if err != nil {
			// A kernel built without one of the two families does not publish its
			// table at all, and an absent family holds no socket.
			continue
		}
		if err := collectListeningPorts(table, product, ports); err != nil {
			return nil, err
		}
		answered = true
	}
	if !answered {
		// Neither family answered, so this machine did not say who holds its
		// sockets. Returning an empty set here would read as "no port is managed",
		// which is the one sentence this constat exists to stop being said by
		// default.
		return nil, errors.New("this machine published no socket table to read")
	}
	return ports, nil
}

// productIdentifiers reads the account table and keeps only the numeric
// identifiers of accounts this product created.
func productIdentifiers(table []byte) map[string]struct{} {
	identifiers := make(map[string]struct{})
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 || !strings.HasPrefix(fields[0], productAccountPrefix) {
			continue
		}
		identifiers[fields[2]] = struct{}{}
	}
	return identifiers
}

// collectListeningPorts keeps the ports of listening sockets held by one of
// those identifiers, and nothing else.
//
// Only the state the kernel writes for a listening socket is kept, so an
// outgoing connection this machine happens to have made from a port never reads
// as a port it publishes. The local address is deliberately not compared: a
// socket bound to every address serves the loopback too, and a reading must not
// call a port free because the thing holding it is holding it more widely.
func collectListeningPorts(table []byte, product map[string]struct{}, ports map[int]struct{}) error {
	lines := strings.Split(string(table), "\n")
	if len(lines) > maxSocketTableEntries {
		return errors.New("the machine's socket table is longer than this reading bounds")
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[3] != listeningSocketState {
			continue
		}
		if _, held := product[fields[7]]; !held {
			continue
		}
		local := fields[1]
		separator := strings.LastIndex(local, ":")
		if separator < 0 {
			continue
		}
		port, err := strconv.ParseUint(local[separator+1:], 16, 32)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		ports[int(port)] = struct{}{}
	}
	return nil
}
