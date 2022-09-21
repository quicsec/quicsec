package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"strings"

	"github.com/quicsec/quicsec/config"
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

func GetIndentityCert() (*tls.Certificate, error) {
	certFile := config.GetPathCertFile()
	keyFile := config.GetPathKeyFile()

	if len(certFile) == 0 || len(keyFile) == 0 {
		return nil, errors.New("auth: must provide certificate, you can configure this via environment variables: `CERT_FILE` and `KEY_FILE`")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)

	return &cert, err
}

// AddRootCA adds the root CA certificate to a cert pool
func AddRootCA(certPool *x509.CertPool) {
	caCertPath := config.GetPathCAFile()

	if len(caCertPath) == 0 {
		panic("auth: must provide CA certificate, you can configure this via environment variable: `CA_FILE`")
	}

	caCertRaw, err := ioutil.ReadFile(caCertPath)

	if err != nil {
		panic(err)
	}

	if ok := certPool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("auth: could not add root ceritificate to pool.")
	}
}
