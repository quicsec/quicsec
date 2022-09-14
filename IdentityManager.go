package quicsec

import (
	"crypto/tls"
	"github.com/quicsec/quicsec/utils"
)

func getIndentityPaths() (string, string) {
	certFile := utils.GetEnv("CERT_FILE", "/data/etc/leaf_cert.crt")
	keyFile := utils.GetEnv("KEY_FILE", "/data/etc/leaf_cert.key")

	return certFile, keyFile
}

func getTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(getIndentityPaths())
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}
