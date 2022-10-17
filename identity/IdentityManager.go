package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/operations/log"
)

func VerifyIdentity(uri string) bool {
	var AuthIDs []string
	AuthIDs = config.GetLastAuthRules()

	for _, id := range AuthIDs {
		v := strings.EqualFold(uri, id)

		if v {
			return true
		}
	}

	return false
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

	caCertRaw, err := ioutil.ReadFile(caCertPath)

	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate %v", err)
	}

	if ok := pool.AppendCertsFromPEM(caCertRaw); !ok {
		return nil, errors.New("could not add root ceritificate to pool")
	}

	return pool, nil
}
