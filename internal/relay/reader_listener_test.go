package relay

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestReaderListenerSlidingRateAndExactSource(t *testing.T) {
	listener, err := NewReaderListener(&stubListener{}, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	for index := 0; index < 12; index++ {
		if !listener.startAllowed(base.Add(time.Duration(index) * time.Second)) {
			t.Fatalf("connection %d inside the twelve-start bound was refused", index+1)
		}
	}
	if listener.startAllowed(base.Add(59 * time.Second)) {
		t.Fatal("thirteenth connection inside the sliding minute was accepted")
	}
	if !listener.startAllowed(base.Add(61 * time.Second)) {
		t.Fatal("expired connection start was not removed from the window")
	}
	if !listener.sourceAllowed(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}) {
		t.Fatal("exact provisioned source was refused")
	}
	if listener.sourceAllowed(&net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 40000}) {
		t.Fatal("neighboring source was accepted")
	}
}

func TestReaderListenerRejectsMissingOrNonIPv4Source(t *testing.T) {
	for _, source := range []string{"", "relay.example", "2001:db8::1"} {
		if _, err := NewReaderListener(&stubListener{}, source); err == nil {
			t.Fatalf("unsafe source %q was accepted", source)
		}
	}
}

type stubListener struct{}

func (*stubListener) Accept() (net.Conn, error) { return nil, errors.New("stub") }
func (*stubListener) Close() error              { return nil }
func (*stubListener) Addr() net.Addr            { return &net.TCPAddr{} }
