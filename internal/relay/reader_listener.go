package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	maxReaderConnections = 4
	maxReaderStarts      = 12
)

// ReaderListener bounds the reader before TLS. nftables remains the first
// network authority; this wrapper independently enforces the exact source,
// concurrency and sliding connection rate in the process.
type ReaderListener struct {
	net.Listener
	allowedSource netip.Addr
	now           func() time.Time
	active        chan struct{}
	mu            sync.Mutex
	starts        []time.Time
}

func NewReaderListener(listener net.Listener, allowedSource string) (*ReaderListener, error) {
	if listener == nil {
		return nil, errors.New("reader listener is required")
	}
	address, err := netip.ParseAddr(allowedSource)
	if err != nil || !address.Is4() {
		return nil, errors.New("reader source must be one exact IPv4 address")
	}
	return &ReaderListener{
		Listener:      listener,
		allowedSource: address,
		now:           time.Now,
		active:        make(chan struct{}, maxReaderConnections),
	}, nil
}

func (listener *ReaderListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		now := listener.now()
		if !listener.sourceAllowed(connection.RemoteAddr()) || !listener.startAllowed(now) {
			_ = connection.Close()
			continue
		}
		select {
		case listener.active <- struct{}{}:
			_ = connection.SetDeadline(now.Add(3 * time.Second))
			return &trackedReaderConnection{Conn: connection, release: listener.leave}, nil
		default:
			_ = connection.Close()
		}
	}
}

func (listener *ReaderListener) sourceAllowed(remote net.Addr) bool {
	tcpAddress, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	address, ok := netip.AddrFromSlice(tcpAddress.IP)
	return ok && address.Unmap() == listener.allowedSource
}

func (listener *ReaderListener) startAllowed(now time.Time) bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	firstCurrent := 0
	for firstCurrent < len(listener.starts) && listener.starts[firstCurrent].Before(cutoff) {
		firstCurrent++
	}
	listener.starts = append(listener.starts[:0], listener.starts[firstCurrent:]...)
	if len(listener.starts) >= maxReaderStarts {
		return false
	}
	listener.starts = append(listener.starts, now)
	return true
}

func (listener *ReaderListener) leave() {
	<-listener.active
}

type trackedReaderConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *trackedReaderConnection) Close() error {
	error := connection.Conn.Close()
	connection.once.Do(connection.release)
	return error
}
