package main

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Un socket unixgram de test qui joue le gestionnaire de services : il rend
// chaque datagramme reçu, pour que les gardes lisent les OCTETS déclarés et
// non un booléen sur leur envoi.
func listenAsServiceManager(t *testing.T) (string, <-chan string) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "notify.sock")
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatalf("service manager socket: %v", err)
	}
	t.Cleanup(func() { connection.Close() })
	received := make(chan string, 1)
	go func() {
		buffer := make([]byte, 64)
		length, _, err := connection.ReadFromUnix(buffer)
		if err != nil {
			return
		}
		received <- string(buffer[:length])
	}()
	return socket, received
}

func TestReadinessIsSilentOutsideAServiceManager(t *testing.T) {
	t.Setenv(readinessSocketEnvironment, "")
	if err := notifyServiceReadiness(); err != nil {
		t.Fatalf("hors gestionnaire, la readiness doit être un silence licite: %v", err)
	}
}

func TestReadinessDeclaresExactlyReadyToTheNamedSocket(t *testing.T) {
	socket, received := listenAsServiceManager(t)
	t.Setenv(readinessSocketEnvironment, socket)
	if err := notifyServiceReadiness(); err != nil {
		t.Fatalf("la déclaration doit atteindre le socket nommé: %v", err)
	}
	select {
	case declaration := <-received:
		if declaration != "READY=1" {
			t.Fatalf("la déclaration doit être exactement READY=1, reçu %q", declaration)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("aucune déclaration reçue par le gestionnaire")
	}
}

func TestAnUnreachableManagerSocketNamesItsRefusal(t *testing.T) {
	t.Setenv(readinessSocketEnvironment, filepath.Join(t.TempDir(), "absent.sock"))
	err := notifyServiceReadiness()
	if err == nil {
		t.Fatal("un socket nommé mais injoignable doit être une erreur nommée")
	}
	if !strings.Contains(err.Error(), "service readiness socket") {
		t.Fatalf("le refus doit nommer le socket de readiness: %v", err)
	}
}

// La garde d'ordre du constat d'activation (#153) : la boucle de service — la
// seule fonction qui ne reçoit que des écouteurs déjà liés — déclare la
// readiness. La retirer d'ici, ou la déplacer avant la liaison, fait rougir
// cette garde : le gestionnaire ne recevrait rien pendant que la boucle sert.
func TestTheServeLoopDeclaresReadinessThenStopsCleanly(t *testing.T) {
	socket, received := listenAsServiceManager(t)
	t.Setenv(readinessSocketEnvironment, socket)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("écouteur de test: %v", err)
	}
	server := &http.Server{Handler: http.NotFoundHandler()}
	outcome := make(chan error, 1)
	go func() {
		outcome <- serveControllerUntilStopped(server, listener, nil, nil, log.New(io.Discard, "", 0))
	}()

	select {
	case declaration := <-received:
		if declaration != "READY=1" {
			t.Fatalf("la boucle doit déclarer READY=1, reçu %q", declaration)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("la boucle sert sans avoir déclaré la readiness")
	}

	// L'arrêt du test passe par la voie que la boucle traite déjà — `Serve`
	// rend `ErrServerClosed` — plutôt que par un signal au processus, que la
	// boucle n'a peut-être pas encore le droit d'intercepter.
	shutdownContext, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatalf("l'arrêt du serveur de test: %v", err)
	}
	select {
	case err := <-outcome:
		if err != nil {
			t.Fatalf("un serveur clos doit conclure la boucle proprement: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("la boucle ne conclut pas sur la clôture du serveur")
	}
}
