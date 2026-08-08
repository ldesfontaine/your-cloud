// The synthetic application of the user service proof, written for this palier
// and for nothing else.
//
// The engine of the third door is what `#121` proves, and a real application
// would prove that application. So this program exists to be exactly, and only,
// what the contract of eligibility describes — and to make every one of those
// sentences readable from outside the machine that runs it:
//
//  1. it runs rootless, holds no capability and asks for none;
//  2. it listens on one port, and the port is the one its definition declares —
//     read from an inert environment line rather than compiled in, so that one
//     image can serve a revision that declares its port correctly and a revision
//     that does not;
//  3. it writes its durable state only under the container paths its definition
//     declares as volumes, and it writes nothing else anywhere;
//  4. it serves under a read-only filesystem: everything it needs to write at
//     start goes either to a volume or to the tmpfs, and it refuses to start when
//     the tmpfs is missing rather than degrading quietly;
//  5. it never opens a connection. It has no client of any kind: the only socket
//     it ever creates is the listener below;
//  6. it takes its configuration from inert environment lines and its one secret
//     from a key the machine generated;
//  7. it is joined by digest, because the only reference that ever names it is
//     the one this proof's origin serves.
//
// **No secret value ever leaves this process.** The generated value is read from
// the environment, used as an HMAC key over one fixed message, and what is served
// is that keyed digest. A reader of the page — or of this proof's log — learns
// that the container holds the value the machine generated, and learns nothing
// about the value. The attestation is what makes "the same secret survived the
// redeployment" a comparison rather than a claim, without the value entering a
// document, a report or an observation.
//
// It is deliberately built with no dependency outside the standard library and
// with CGO disabled: the image that carries it holds one file and nothing else,
// so nothing of a third party enters this proof.
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// attestationMessage is the fixed message the generated value keys. It is a
	// constant so that two runs of this program over one value produce one
	// attestation, and it is domain-separated so that the digest served here can
	// never be mistaken for the digest of anything else in this product.
	attestationMessage = "your-cloud/lab-user-service-attestation.v1"

	// contentFileName is the file the application creates under its content
	// volume the first time it starts, and never rewrites afterwards. It is what
	// the corruption of this proof damages and what a return brings back.
	contentFileName = "content.txt"

	// bootsFileName is the file the application appends one line to at every
	// start, under its state volume. It is what says a new container really ran
	// in front of the very same bytes.
	bootsFileName = "boots.log"

	// scratchFileName is what the application writes into the tmpfs before it
	// listens. The write is the requirement, not the file: an image that cannot
	// write here does not serve, which is what makes the tmpfs of the definition
	// a declared need rather than a decoration.
	scratchFileName = "started"
)

// environment names every line this application reads. Every one of them is a
// line of the definition, and none of them is a value this program chooses: the
// paths are the container paths the definition declares, the port is the port it
// declares, the origin is the one the plan approved and the definition
// interpolated, and the token is the key the machine generated.
const (
	slugVariable    = "YC_LAB_SLUG"
	portVariable    = "YC_LAB_LISTEN_PORT"
	originVariable  = "YC_LAB_ORIGIN"
	scratchVariable = "YC_LAB_SCRATCH_DIR"
	stateVariable   = "YC_LAB_STATE_DIR"
	contentVariable = "YC_LAB_CONTENT_DIR"
	payloadVariable = "YC_LAB_CONTENT"
	tokenVariable   = "YC_LAB_TOKEN"
)

func main() {
	if err := serve(); err != nil {
		fmt.Fprintf(os.Stderr, "your-cloud lab synthetic application: %v\n", err)
		os.Exit(1)
	}
}

func serve() error {
	port, err := strconv.Atoi(strings.TrimSpace(os.Getenv(portVariable)))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%s must name the port this image listens on", portVariable)
	}

	// The tmpfs first, and it is a hard requirement rather than a preference. A
	// definition that declares no tmpfs leaves this path absent under a read-only
	// filesystem, and this program refuses to serve rather than pretending it
	// started: what an image needs to write outside its data is declared by its
	// author, and the failure of a revision that forgot to declare it belongs to
	// that revision.
	scratch := os.Getenv(scratchVariable)
	if scratch == "" {
		return fmt.Errorf("%s must name the in-memory scratch this image requires", scratchVariable)
	}
	if err := os.WriteFile(filepath.Join(scratch, scratchFileName),
		[]byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		return fmt.Errorf("this image requires a writable %s and this one is not: %w", scratch, err)
	}

	// The durable state. A definition that declares no volume leaves both of these
	// empty, and this application then keeps nothing at all — which is a shape the
	// contract admits and this proof exercises beside the one that keeps data.
	boots := 0
	if state := os.Getenv(stateVariable); state != "" {
		boots, err = recordBoot(filepath.Join(state, bootsFileName))
		if err != nil {
			return err
		}
	}
	content := ""
	if directory := os.Getenv(contentVariable); directory != "" {
		content, err = ensureContent(filepath.Join(directory, contentFileName),
			os.Getenv(payloadVariable))
		if err != nil {
			return err
		}
	}

	page := renderPage(boots, content)
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusOK)
		fmt.Fprint(response, page)
	})
	server := &http.Server{
		Addr:              net.JoinHostPort("0.0.0.0", strconv.Itoa(port)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// An eighth sentence the contract of eligibility does not spell and every
	// managed service of this product needs: **stop cleanly when asked to stop.**
	// A container that dies of its termination signal exits non-zero, and the unit
	// that ran it stays `failed` in its account's own manager afterwards — through
	// an archive, which stops and starts the service, and after a removal, which
	// takes the sheet away and leaves that state behind. Nothing of the product is
	// wrong there: what it removes is what it wrote. But an image that answers a
	// stop with a failure makes every reading of "the service is inactive" say
	// "failed" instead, and a synthetic application built to demonstrate the
	// contract has no business being the one image that does not.
	stopping := make(chan os.Signal, 1)
	signal.Notify(stopping, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stopping
		context, release := context.WithTimeout(context.Background(), 5*time.Second)
		defer release()
		server.Shutdown(context)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// recordBoot appends one line to the durable state and answers how many starts
// this application has now recorded. The count is what distinguishes a container
// that was recreated from one that never stopped, read from the data itself
// rather than from the engine.
func recordBoot(path string) (int, error) {
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("this image requires a writable state volume: %w", err)
	}
	if _, err := fmt.Fprintf(handle, "started %s\n", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		handle.Close()
		return 0, err
	}
	if err := handle.Close(); err != nil {
		return 0, err
	}
	return countLines(path)
}

func countLines(path string) (int, error) {
	handle, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer handle.Close()
	lines := 0
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		lines++
	}
	return lines, scanner.Err()
}

// ensureContent writes the declared payload the first time and never again, so
// that what a later step of this proof damages and returns from is a file this
// application created once and has read ever since.
func ensureContent(path, payload string) (string, error) {
	existing, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimRight(string(existing), "\n"), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if payload == "" {
		payload = "your-cloud lab synthetic content"
	}
	if err := os.WriteFile(path, []byte(payload+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("this image requires a writable content volume: %w", err)
	}
	return payload, nil
}

// renderPage is everything a client outside this machine may read of this
// application, and it is fixed at start rather than recomputed per request: what
// is served is what the container found when it started, so a reader learns the
// state of one container rather than of a directory somebody may be editing.
//
// The token line is an attestation and never a value. `absent` says the container
// received no generated value at all, which is the honest reading for a
// definition that declares no secret key.
func renderPage(boots int, content string) string {
	builder := &strings.Builder{}
	fmt.Fprintf(builder, "your-cloud LAB synthetic application\n")
	fmt.Fprintf(builder, "slug=%s\n", os.Getenv(slugVariable))
	fmt.Fprintf(builder, "origin=%s\n", os.Getenv(originVariable))
	fmt.Fprintf(builder, "scratch=writable\n")
	fmt.Fprintf(builder, "content=%s\n", content)
	fmt.Fprintf(builder, "boots=%d\n", boots)
	fmt.Fprintf(builder, "token=%s\n", attestation(os.Getenv(tokenVariable)))
	return builder.String()
}

// attestation proves possession of the generated value without carrying it. The
// value is the key of an HMAC over one fixed message; the digest travels, the
// value does not, and no inversion of the digest returns the value.
func attestation(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "absent"
	}
	mac := hmac.New(sha256.New, []byte(trimmed))
	mac.Write([]byte(attestationMessage))
	return "attested:" + hex.EncodeToString(mac.Sum(nil))
}
