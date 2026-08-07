package external

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ldesfontaine/your-cloud/internal/observation"
)

type closedReader struct {
	*bytes.Reader
	closed bool
}

func (reader *closedReader) Close() error {
	reader.closed = true
	return nil
}

func payload(size int) *closedReader {
	return &closedReader{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), size))}
}

// TestAdapterReadsWithoutTheMeansToWrite is the structural proof of `#107`, and
// it is three separate arguments about the same file.
//
// The first is the file's imports, held to an exact list rather than to a list of
// forbidden names: `probe.go` receives context, errors and io, and no fourth
// package exists through which it could reach a filesystem, a process, a socket
// of its own or a store. The second is the seam: what the adapter is handed
// returns an io.ReadCloser, whose method set is Read and Close — there is no
// Write on it, so the adapter cannot send a byte to the thing it reads, and no
// host, scheme or path travels either. The third is the type: an Adapter holds
// exactly one field, that seam, and nothing else at all.
//
// A code that is not given the means to write cannot write, and this is what
// "not given" means here.
func TestAdapterReadsWithoutTheMeansToWrite(t *testing.T) {
	t.Parallel()
	file, err := parser.ParseFile(token.NewFileSet(), "probe.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{`"context"`, `"errors"`, `"io"`}
	imported := make([]string, 0, len(file.Imports))
	for _, entry := range file.Imports {
		imported = append(imported, entry.Path.Value)
	}
	sort.Strings(imported)
	if !reflect.DeepEqual(imported, allowed) {
		t.Fatalf("probe.go imports %v rather than exactly %v", imported, allowed)
	}

	stream := reflect.TypeOf(Open(nil)).Out(0)
	if stream != reflect.TypeOf((*io.ReadCloser)(nil)).Elem() {
		t.Fatalf("the read seam yields %s rather than an io.ReadCloser", stream)
	}
	methods := make([]string, 0, stream.NumMethod())
	for index := 0; index < stream.NumMethod(); index++ {
		methods = append(methods, stream.Method(index).Name)
	}
	sort.Strings(methods)
	if !reflect.DeepEqual(methods, []string{"Close", "Read"}) {
		t.Fatalf("the read seam yields something that can do %v", methods)
	}
	if fields := reflect.TypeOf(Adapter{}).NumField(); fields != 1 {
		t.Fatalf("an adapter holds %d values rather than its one bounded read", fields)
	}
}

// TestPackageReachesNoEffectAndNoPlan holds the whole package to what it may
// touch, file by file.
//
// Only the one file that binds this package to a machine may name the operating
// system or the network at all, and no file anywhere may reach a plan, an
// approval, the Auxiliary or the Controller. HTTP and TLS are absent from every
// file, which is how "no redirect is followed" and "no trust decision is taken"
// become properties of the program rather than promises: there is no client here
// that could follow anything.
func TestPackageReachesNoEffectAndNoPlan(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		`"os/exec"`, `"net/http"`, `"crypto/tls"`, `"syscall"`,
		"internal/plan", "internal/approval", "internal/auxiliary",
		"internal/controller", "internal/buffer", "internal/relay",
	}
	machineOnly := []string{`"os"`, `"net"`, "internal/securefile"}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range file.Imports {
			for _, refused := range forbidden {
				if strings.Contains(entry.Path.Value, refused) {
					t.Fatalf("%s imports %s: a read-only adapter has no path to an effect", name, refused)
				}
			}
			if name == "sight.go" {
				continue
			}
			for _, bound := range machineOnly {
				if strings.Contains(entry.Path.Value, bound) {
					t.Fatalf("%s imports %s: only sight.go may touch this machine", name, bound)
				}
			}
		}
	}
}

// TestAdapterConcludesOnlyAboutTheConnection walks the three conclusions the
// adapter itself may reach, and proves the one it may never reach: a conclusion
// about the content.
//
// Two answers of the same length carrying entirely different bytes produce the
// same reading, because nothing is interpreted. An answer that goes past the
// bound is cut and reported as cut rather than called a success, and the stream
// is closed in every case.
func TestAdapterConcludesOnlyAboutTheConnection(t *testing.T) {
	t.Parallel()
	answers := map[string]*closedReader{
		"empty":        payload(0),
		"small":        {Reader: bytes.NewReader([]byte("<script>alert(1)</script>"))},
		"other":        {Reader: bytes.NewReader([]byte("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18"))},
		"at the bound": payload(maxResponseBytes),
	}
	for name, answer := range answers {
		adapter, err := NewAdapter(func(context.Context, int) (io.ReadCloser, error) { return answer, nil })
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := adapter.Read(context.Background(), 5000)
		if err != nil || outcome != observation.ExternalAnswered {
			t.Fatalf("%s produced %q (%v) rather than an answered connection", name, outcome, err)
		}
		if !answer.closed {
			t.Fatalf("%s left the connection open", name)
		}
	}

	tooLarge := payload(maxResponseBytes + 1)
	adapter, err := NewAdapter(func(context.Context, int) (io.ReadCloser, error) { return tooLarge, nil })
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _ := adapter.Read(context.Background(), 5000); outcome != observation.ExternalTooLarge {
		t.Fatalf("an answer past the bound read as %q", outcome)
	}

	refused, err := NewAdapter(func(context.Context, int) (io.ReadCloser, error) {
		return nil, errors.New("connection refused")
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _ := refused.Read(context.Background(), 5000); outcome != observation.ExternalNoListener {
		t.Fatalf("a refused connection read as %q", outcome)
	}
	if _, err := refused.Read(context.Background(), 0); err == nil {
		t.Fatal("a port outside 1..65535 was read")
	}
	if _, err := NewAdapter(nil); err == nil {
		t.Fatal("an adapter with no way to read was built")
	}
}

// TestSystemSightReadsOneRealLoopbackPort proves the binding itself rather than
// a fake of it: a real listener on this machine's loopback is answered, and the
// port it stopped holding is not.
func TestSystemSightReadsOneRealLoopbackPort(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", LoopbackAddress+":0")
	if err != nil {
		t.Skipf("this machine refuses a loopback listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	adapter, err := NewAdapter(SystemSight().Open)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := adapter.Read(context.Background(), port); err != nil || outcome != observation.ExternalAnswered {
		t.Fatalf("a real listener read as %q (%v)", outcome, err)
	}
	listener.Close()
	if outcome, _ := adapter.Read(context.Background(), port); outcome != observation.ExternalNoListener {
		t.Fatalf("a port nothing holds read as %q", outcome)
	}
	if _, err := SystemSight().ReadFile("/etc/shadow"); err == nil {
		t.Fatal("the reading opened a path of its own")
	}
}
