package identity

import (
	"crypto/tls"
	"github.com/quicsec/quicsec/utils"
)

func GetIndentityPaths() (string, string) {
	certFile := utils.GetEnv("CERT_FILE", "/data/etc/leaf_cert.crt")
	keyFile := utils.GetEnv("KEY_FILE", "/data/etc/leaf_cert.key")

	return certFile, keyFile
}

func GetTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(GetIndentityPaths())
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}
