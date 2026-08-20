package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ldesfontaine/your-cloud/internal/readeridentity"
)

// La paire du lecteur naît ici, chez celui qu'elle identifie, et sa moitié
// privée ne voyage jamais — ni dans un document, ni dans une observation, ni
// dans un argument de processus. C'est la décision du 20 août 2026 (constat de
// la preuve du palier v0.1.3) : `LoadCredential=` est une contrainte de forme,
// pas d'autorité — la frappe précède le premier démarrage de l'unité, sous
// l'acte nommé du plan que l'humain a approuvé.
//
// Le certificat est AUTO-SIGNÉ, et ce n'est pas un pis-aller : l'autorisation
// côté Relay (`readeridentity.Manifest.Authorize`) épingle la feuille exacte —
// URI canonique, numéro de série, empreinte SHA-256 du DER — et ne chaîne
// jamais vers une autorité. Le modèle est celui de la clé d'hôte relevée :
// la confiance naît d'une empreinte constatée sous un consentement, pas d'une
// hiérarchie. Les attributs sont exactement ceux que l'autorisation exige :
// feuille (jamais CA), signature numérique seule, `clientAuth` seul, une seule
// URI.
//
// La validité est longue à dessein : le renouvellement automatique est
// explicitement hors de ce palier (contrat de la chaîne d'observation), et la
// révocation vit dans le manifeste du Relay — retirer l'épinglage suffit, le
// certificat n'est une autorité pour personne.
const readerCertificateValidity = 20 * 365 * 24 * time.Hour

const (
	readerCertificateName = "controller-reader.crt"
	readerKeyName         = "controller-reader.key"
	readerFileMode        = 0o600
)

// MintedReaderIdentity est ce qui peut quitter cette machine : des
// identifiants et des empreintes, jamais une clé.
type MintedReaderIdentity struct {
	ControllerID      string
	InfrastructureID  string
	CertificateSerial string
	CertificateSHA256 string
}

// MintReaderIdentity frappe la paire du lecteur de ce Controller dans le
// répertoire des sources de credentials, et refuse de refrapper : une paire
// déjà présente est une rotation, pas une frappe, et la rotation appartient à
// un palier qui saura la révoquer.
//
// L'autorité doit exister — les identifiants immuables entrent dans l'URI du
// certificat — donc la frappe vient après l'initialisation, ce que l'ordre du
// plan tient.
func MintReaderIdentity(
	stateDirectory string,
	credentialsDirectory string,
	entropy io.Reader,
	now time.Time,
) (MintedReaderIdentity, error) {
	if !filepath.IsAbs(credentialsDirectory) || filepath.Clean(credentialsDirectory) != credentialsDirectory {
		return MintedReaderIdentity{}, errors.New("the reader credentials directory must be absolute and canonical")
	}
	authority, err := OpenAuthorityStore(stateDirectory, now)
	if err != nil {
		return MintedReaderIdentity{}, fmt.Errorf("reader identity needs the initialised authority: %w", err)
	}
	state := authority.Snapshot()
	if entropy == nil {
		entropy = rand.Reader
	}

	certificatePath := filepath.Join(credentialsDirectory, readerCertificateName)
	keyPath := filepath.Join(credentialsDirectory, readerKeyName)
	for _, path := range []string{certificatePath, keyPath} {
		if _, err := os.Lstat(path); err == nil {
			return MintedReaderIdentity{}, fmt.Errorf(
				"this Controller already holds %q; replacing it is a rotation, not a mint", filepath.Base(path))
		} else if !errors.Is(err, os.ErrNotExist) {
			return MintedReaderIdentity{}, err
		}
	}

	public, private, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return MintedReaderIdentity{}, err
	}
	serial, err := rand.Int(entropy, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return MintedReaderIdentity{}, err
	}
	if serial.Sign() <= 0 {
		// L'autorisation canonicalise une série strictement positive ; zéro —
		// improbable mais tiré — serait refusé là-bas, donc refusé ici.
		serial = big.NewInt(1)
	}
	identity, err := url.Parse(readeridentity.URI(state.InfrastructureID, state.ControllerID))
	if err != nil {
		return MintedReaderIdentity{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "your-cloud-controller-reader"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(readerCertificateValidity),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identity},
	}
	certificateDER, err := x509.CreateCertificate(entropy, template, template, public, private)
	if err != nil {
		return MintedReaderIdentity{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return MintedReaderIdentity{}, err
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	// La clé d'abord : si son écriture échoue, aucun certificat orphelin ne
	// laisse croire qu'une identité existe. Chaque fichier naît exclusif, mode
	// posé avant le premier octet, et un échec retire ce qui vient d'être créé.
	if err := writeExclusive(keyPath, keyPEM); err != nil {
		return MintedReaderIdentity{}, err
	}
	if err := writeExclusive(certificatePath, certificatePEM); err != nil {
		_ = os.Remove(keyPath)
		return MintedReaderIdentity{}, err
	}

	digest := sha256.Sum256(certificateDER)
	return MintedReaderIdentity{
		ControllerID:     state.ControllerID,
		InfrastructureID: state.InfrastructureID,
		// Les deux formats sont ceux que le manifeste du Relay épinglera :
		// la série par le canon même de l'autorisation, l'empreinte en
		// hexadécimal minuscule du DER.
		CertificateSerial: readeridentity.CanonicalSerial(serial),
		CertificateSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func writeExclusive(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, readerFileMode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
