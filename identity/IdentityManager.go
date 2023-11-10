package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/spiffeid"
)

// return[0] - true (authorized) - false (unauthorized)
// return[1] - "strict"/"default"
func VerifyIdentity(uri string) (bool, string) {
	var AuthIDs map[string]bool
	AuthIDs, dFlag := config.GetLastAuthRules()

	// strict rules
	for key, allow := range AuthIDs {
		v := strings.EqualFold(uri, key)

		if v {
			if allow {
				return true, "strict"
			} else {
				return false, "strict"
			}
		}
	}

	// default rules
	if dFlag {
		return true, "default"
	} else {
		return false, "default"
	}
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

func getSecretManager(name string) (string, error) {
	regionName := os.Getenv("AWS_DEFAULT_REGION")

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(regionName),
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Session creation failed: %s", err)
		return "", err
	}

	svc := secretsmanager.New(sess)

	input := secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	}

	resp, err := svc.GetSecretValue(&input)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to get secret: %s", err)
		return "", err
	}

	return aws.StringValue(resp.SecretString), nil
}

func GetCert() (*tls.Certificate, error) {
	if config.GetCertsMethod() == "aws" {
		return GetCertAws()
	}
	return GetCertDisk()
}

func GetCertPool() (*x509.CertPool, error) {
	if config.GetCertsMethod() == "aws" {
		return GetCertPoolAws()
	}
	return GetCertPoolDisk()
}

func GetCertDisk() (*tls.Certificate, error) {
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

func GetCertAws() (*tls.Certificate, error) {
	cert_name := config.GetPathCertFile()
	key_name := config.GetPathKeyFile()

	if len(cert_name) == 0 || len(key_name) == 0 {
		return nil, errors.New("must provide certificate and key")
	}

	certPEM, err := getSecretManager(cert_name)
	if err != nil {
		fmt.Println("Error:\n", err)
	}

	keyPEM, err := getSecretManager(key_name)
	if err != nil {
		fmt.Println("Error:\n", err)
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		err = fmt.Errorf("failed trying to load x509 key pair %v", err)
	}

	return &cert, err
}

func GetCertPoolAws() (*x509.CertPool, error) {
	idLogger := log.LoggerLgr.WithName(log.ConstConnManager)

	pool, err := x509.SystemCertPool()

	if err != nil {
		idLogger.Error(err, "failed to get system cert pool")
		return nil, err
	}

	ca_name := config.GetPathCAFile()

	if len(ca_name) == 0 {
		return nil, errors.New("must provide CA certificate")
	}

	caPEM, err := getSecretManager(ca_name)
	if err != nil {
		fmt.Println("Error:\n", err)
	}

	if ok := pool.AppendCertsFromPEM([]byte(caPEM)); !ok {
		return nil, errors.New("could not add root ceritificate to pool")
	}

	return pool, nil
}

func GetCertPoolDisk() (*x509.CertPool, error) {
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
