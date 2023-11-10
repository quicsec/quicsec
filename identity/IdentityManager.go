package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/spiffeid"
)

func AllowedIdentity(uri string) bool {
	for _, allowed := range config.GetAllowedIdentities() {
		if allowed == uri {
			return true
		}
	}

	return false
}

func GetCurrentIdentity() (spiffeid.ID, error) {
	tlsCert, tlsCertErr := GetCert()
	if tlsCertErr == nil {
		x509Cert, _ := x509.ParseCertificate(tlsCert.Certificate[0])
		serverId, err := IDFromCert(x509Cert)
		return serverId, err
	}
	return spiffeid.ID{}, tlsCertErr
}

// IDFromCert extracts the SPIFFE ID from the URI SAN of the provided
// certificate. It will return an an error if the certificate does not have
// exactly one URI SAN with a well-formed SPIFFE ID.
func IDFromCert(cert *x509.Certificate) (spiffeid.ID, error) {
	switch {
	case len(cert.URIs) == 0:
		return spiffeid.ID{}, errors.New("certificate contains no URI SAN")
	case len(cert.URIs) > 1:
		return spiffeid.ID{}, errors.New("certificate contains more than one URI SAN")
	}
	return spiffeid.FromURI(cert.URIs[0])
}

func GetCert() (*tls.Certificate, error) {
	certFile := config.GetPathCertFile()
	keyFile := config.GetPathKeyFile()

	if len(certFile) == 0 || len(keyFile) == 0 {
		return nil, errors.New("must provide certificate, you can configure this via environment variables: `CERT_FILE` and `KEY_FILE`")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)

	if err != nil {
		err = fmt.Errorf("failed trying to load x509 key pair %v", err)
	}

	return &cert, err
}

func GetCertPool() (*x509.CertPool, error) {
	idLogger := log.LoggerLgr.WithName(log.ConstConnManager)

	pool, err := x509.SystemCertPool()

	if err != nil {
		idLogger.Error(err, "failed to get system cert pool")
		return nil, err
	}

	caCertPath := config.GetPathCAFile()

	if len(caCertPath) == 0 {
		return nil, errors.New("must provide CA certificate, you can configure this via environment variable: `CA_FILE`")
	}

	caCertRaw, err := os.ReadFile(caCertPath)

	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate %v", err)
	}

	if ok := pool.AppendCertsFromPEM(caCertRaw); !ok {
		return nil, errors.New("could not add root ceritificate to pool")
	}

	return pool, nil
}
