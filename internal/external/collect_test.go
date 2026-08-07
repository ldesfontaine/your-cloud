package external

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

const testAccounts = "root:x:0:0::/root:/bin/bash\n" +
	"your-cloud-svc-bentopdf:x:998:998::/var/lib/your-cloud-svc-bentopdf:/usr/sbin/nologin\n" +
	"someone:x:1000:1000::/home/someone:/bin/bash\n"

// A listening socket of the product on 8443, one of a stranger on 5000, and one
// outgoing connection of the product that holds no port at all.
const testSockets = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
	"   0: 0100007F:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   998        0 111 1\n" +
	"   1: 0100007F:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 112 1\n" +
	"   2: 0100007F:C000 0100007F:0050 01 00000000:00000000 00:00000000 00000000   998        0 113 1\n"

func testSight(t *testing.T, sheet string, opened *[]int) Sight {
	t.Helper()
	return Sight{
		ReadFile: func(path string) ([]byte, error) {
			switch path {
			case TargetsPath:
				if sheet == "" {
					return nil, errors.New("no such file")
				}
				return []byte(sheet), nil
			case accountTablePath:
				return []byte(testAccounts), nil
			case tcpTablePath:
				return []byte(testSockets), nil
			case tcp6TablePath:
				return nil, errors.New("no such file")
			}
			return nil, errors.New("unexpected path " + path)
		},
		Open: func(_ context.Context, port int) (io.ReadCloser, error) {
			*opened = append(*opened, port)
			if port == 5000 {
				return &closedReader{Reader: bytes.NewReader(nil)}, nil
			}
			return nil, errors.New("connection refused")
		},
	}
}

// TestCollectReadsOnlyDeclaredTargets is the collection as a whole: the sheet
// decides what is looked at, the kernel decides what belongs to this product,
// and nothing else on this machine is discovered, named or connected to.
//
// The port a managed service holds is reported as managed and is never connected
// to at all — the reading that would have followed could only have said
// "something answered", which is exactly the sentence that would let a managed
// service pass for an external one.
func TestCollectReadsOnlyDeclaredTargets(t *testing.T) {
	t.Parallel()
	var opened []int
	sheet := `{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[5000,8443,9000]}`
	readings, err := Collect(context.Background(), testSight(t, sheet, &opened), "lab-machine-1")
	if err != nil {
		t.Fatal(err)
	}
	expected := []observation.ExternalReading{
		{ProbePort: 5000, Outcome: observation.ExternalAnswered},
		{ProbePort: 8443, Outcome: observation.ExternalManaged},
		{ProbePort: 9000, Outcome: observation.ExternalNoListener},
	}
	if len(readings) != len(expected) {
		t.Fatalf("the collection produced %+v", readings)
	}
	for index, reading := range readings {
		if reading != expected[index] {
			t.Fatalf("reading %d is %+v rather than %+v", index, reading, expected[index])
		}
	}
	for _, port := range opened {
		if port == 8443 {
			t.Fatal("a port this product holds was connected to")
		}
	}
	// What the collection produced is exactly what the wire accepts: bounded,
	// sorted, unique, closed on its four words, and inside the message the three
	// collectors already fit in.
	value := uint64(1)
	envelope, err := observation.NewEnvelope("lab-machine-1", 1, time.Unix(0, 0).UTC(), observation.HostHealth{
		Uptime: observation.UptimeResult{Status: "ok", UptimeSeconds: &value},
		Memory: observation.MemoryResult{Status: "ok", TotalBytes: &value, AvailableBytes: &value},
		RootFS: observation.RootFSResult{Status: "ok", TotalBytes: &value, AvailableBytes: &value},
	}, readings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Encode(); err != nil {
		t.Fatal(err)
	}
}

// TestCollectSaysNothingRatherThanGuessing is the fail-closed half.
//
// A machine with no sheet looks at nothing and reports nothing, which is how a
// neighbour nobody declared stays unknown: there is no scan, no range and no
// discovery anywhere in this package. A machine whose account table cannot be
// read reports nothing either, because a machine that cannot say who holds its
// sockets has not answered — answering "no managed port" there would be the
// silent presentation the collision refusal exists to prevent.
func TestCollectSaysNothingRatherThanGuessing(t *testing.T) {
	t.Parallel()
	var opened []int
	readings, err := Collect(context.Background(), testSight(t, "", &opened), "lab-machine-1")
	if err != nil || readings != nil || len(opened) != 0 {
		t.Fatalf("a machine with no sheet produced %+v (%v) after opening %v", readings, err, opened)
	}

	blind := testSight(t, `{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[5000]}`, &opened)
	inner := blind.ReadFile
	blind.ReadFile = func(path string) ([]byte, error) {
		if path == accountTablePath {
			return nil, errors.New("permission denied")
		}
		return inner(path)
	}
	if _, err := Collect(context.Background(), blind, "lab-machine-1"); err == nil {
		t.Fatal("a machine that cannot name its own accounts reported readings anyway")
	}
	if _, err := Collect(context.Background(), Sight{}, "lab-machine-1"); err == nil {
		t.Fatal("a collection ran with neither of its two bounded reads")
	}
}

// TestTargetsSheetIsClosedAndBelongsToItsMachine holds the observation profile to
// what it may say. A sheet copied from another machine is refused above all: the
// Controller keys a reading on the pair of a machine and a port, so a viewpoint
// that could be moved by copying a file would not be a viewpoint.
func TestTargetsSheetIsClosedAndBelongsToItsMachine(t *testing.T) {
	t.Parallel()
	for name, sheet := range map[string]string{
		"another machine":  `{"schema_version":1,"machine_id":"lab-machine-2","probe_ports":[5000]}`,
		"another schema":   `{"schema_version":2,"machine_id":"lab-machine-1","probe_ports":[5000]}`,
		"unsorted":         `{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[9000,5000]}`,
		"repeated":         `{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[5000,5000]}`,
		"port zero":        `{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[0]}`,
		"absent ports":     `{"schema_version":1,"machine_id":"lab-machine-1"}`,
		"an address field": `{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[5000],"host":"10.0.0.1"}`,
		"empty":            ``,
	} {
		if _, err := DecodeTargets([]byte(sheet), "lab-machine-1"); err == nil {
			t.Fatalf("a sheet with %s was accepted", name)
		}
	}
	targets, err := DecodeTargets(
		[]byte(`{"schema_version":1,"machine_id":"lab-machine-1","probe_ports":[]}`), "lab-machine-1")
	if err != nil || len(targets.ProbePorts) != 0 {
		t.Fatalf("a sheet naming no target was refused: %+v %v", targets, err)
	}
}
