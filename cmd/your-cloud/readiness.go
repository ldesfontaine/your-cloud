package main

import (
	"fmt"
	"net"
	"os"
)

// Le nom que systemd donne au socket de son gestionnaire quand l'unité est
// `Type=notify`. Hors d'un gestionnaire de services, il n'est pas posé.
const readinessSocketEnvironment = "NOTIFY_SOCKET"

// Déclare « READY=1 » au gestionnaire de services, et reste silencieuse
// partout ailleurs.
//
// C'est la moitié serveur du constat d'activation (#153) : « actif » cesse
// d'être un instantané pris pendant qu'un service qui va retomber ne l'a pas
// encore fait, et devient une déclaration du service lui-même — émise
// seulement une fois ses écouteurs liés. Un `serve` qui refuse sa
// configuration sort AVANT de la faire, donc `systemctl start` échoue au lieu
// de rendre un « active » transitoire.
//
// Un socket nommé mais injoignable est une erreur nommée, jamais un silence :
// sous `Type=notify`, ne rien déclarer laisserait l'unité en `activating`
// jusqu'au timeout, et la cause doit se lire.
func notifyServiceReadiness() error {
	socket := os.Getenv(readinessSocketEnvironment)
	if socket == "" {
		return nil
	}
	// La convention sd_notify : un premier octet « @ » nomme un socket
	// abstrait Linux, dont l'adresse réelle commence par un octet nul.
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("service readiness socket: %w", err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("READY=1")); err != nil {
		return fmt.Errorf("service readiness declaration: %w", err)
	}
	return nil
}
