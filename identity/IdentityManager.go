package identity

import (
	"crypto/tls"
	"errors"

	"github.com/quicsec/quicsec/utils"
)

func GetIndentityCert() (*tls.Certificate, error) {
	certFile := utils.GetEnv("CERT_FILE", "")
	keyFile := utils.GetEnv("KEY_FILE", "")

	if len(certFile) == 0 || len(keyFile) == 0 {
		return nil, errors.New("tls: must provide certificate on production mode, you can configure this via environment variables: `CERT_FILE` and `KEY_FILE`")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)

	return &cert, err
}
