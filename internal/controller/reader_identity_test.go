package controller

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/readeridentity"
)

func initialisedState(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeAuthority(directory, time.Now()); err != nil {
		t.Fatal(err)
	}
	return directory
}

// La boucle entière, jugée par le juge d'en face : la feuille frappée ici doit
// passer l'autorisation du Relay avec un manifeste construit des seules
// valeurs que la frappe imprime. Si la naissance et l'autorisation divergent
// d'un octet — URI, série, empreinte, usages — ce cas rougit ; c'est lui qui
// tient « le précédent de la clé d'hôte » : la confiance par empreinte
// constatée, sans autorité intermédiaire.
func TestMintedReaderIdentityIsAuthorizedByTheRelayJudgeItself(t *testing.T) {
	state := initialisedState(t)
	credentials := t.TempDir()

	minted, err := MintReaderIdentity(state, credentials, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(credentials, "controller-reader.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("the minted certificate is not a PEM CERTIFICATE")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	manifest := &readeridentity.Manifest{
		SchemaVersion:     1,
		URI:               readeridentity.URI(minted.InfrastructureID, minted.ControllerID),
		CertificateSerial: minted.CertificateSerial,
		CertificateSHA256: minted.CertificateSHA256,
		Status:            "active",
	}
	if err := manifest.Authorize(certificate, time.Now()); err != nil {
		t.Fatalf("the relay judge refuses the minted leaf: %v", err)
	}
}

// La clé privée naît 0600, la frappe est exclusive, et refrapper est une
// rotation refusée — les trois bornes qui font d'une frappe un acte et non un
// état qu'on écrase.
func TestMintingIsExclusiveAndTheKeyIsBornPrivate(t *testing.T) {
	state := initialisedState(t)
	credentials := t.TempDir()

	if _, err := MintReaderIdentity(state, credentials, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(credentials, "controller-reader.key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("the private half was born %o rather than 0600", mode)
	}

	if _, err := MintReaderIdentity(state, credentials, nil, time.Now()); err == nil {
		t.Fatal("a second mint over an existing pair must be refused as a rotation")
	}
}

// Sans autorité initialisée, aucune frappe : l'URI porte les identifiants
// immuables, donc l'ordre du plan — init d'abord — est tenu par un refus, pas
// par une convention.
func TestMintingRefusesAnUninitialisedState(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := MintReaderIdentity(directory, t.TempDir(), nil, time.Now()); err == nil {
		t.Fatal("minting without the initialised authority must be refused")
	}
}
