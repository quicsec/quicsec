package auth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/spiffeid"
)

type verifyOption func(config *verifyConfig)

type verifyConfig struct {
	now time.Time
}

// VerifyOption is an option used when verifying X509-SVIDs.
type VerifyOption interface {
	apply(config *verifyConfig)
}

func (fn verifyOption) apply(config *verifyConfig) {
	fn(config)
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

// Verify verifies an X509-SVID chain using the X.509 bundle source. It
// returns the SPIFFE ID of the X509-SVID and one or more chains back to a root
// in the bundle.
func Verify(certs []*x509.Certificate, pool *x509.CertPool, opts ...VerifyOption) (spiffeid.ID, [][]*x509.Certificate, error) {
	config := &verifyConfig{}
	for _, opt := range opts {
		opt.apply(config)
	}

	switch {
	case len(certs) == 0:
		return spiffeid.ID{}, nil, errors.New("empty certificates chain")
	case pool == nil:
		return spiffeid.ID{}, nil, errors.New("pool is required")
	}

	leaf := certs[0]
	id, err := IDFromCert(leaf)
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("could not get leaf SPIFFE ID: %s", err)
	}

	switch {
	case leaf.IsCA:
		return id, nil, errors.New("leaf certificate with CA flag set to true")
	case leaf.KeyUsage&x509.KeyUsageCertSign > 0:
		return id, nil, errors.New("leaf certificate with KeyCertSign key usage")
	case leaf.KeyUsage&x509.KeyUsageCRLSign > 0:
		return id, nil, errors.New("leaf certificate with KeyCrlSign key usage")
	}

	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: NewCertPool(certs[1:]),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   config.now,
	})
	if err != nil {
		return id, nil, fmt.Errorf("auth: could not verify leaf certificate: %w", err)
	}

	return id, verifiedChains, nil
}

// ParseAndVerify parses and verifies an X509-SVID chain using the X.509
// bundle source. It returns the SPIFFE ID of the X509-SVID and one or more
// chains back to a root in the bundle.
func ParseAndVerify(rawCerts [][]byte, pool *x509.CertPool) (spiffeid.ID, [][]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return spiffeid.ID{}, nil, fmt.Errorf("unable to parse certificate: %w", err)

		}
		certs = append(certs, cert)
	}
	return Verify(certs, pool)
}

// VerifyPeerCertificate returns a VerifyPeerCertificate callback for
// tls.Config. It uses the given bundle source and authorizer to verify and
// authorize X509-SVIDs provided by peers during the TLS handshake.
func VerifyPeerCertificate(pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, _, err := ParseAndVerify(raw, pool)

		return err
	}
}

// WrapVerifyPeerCertificate wraps a VeriyPeerCertificate callback, performing
// SPIFFE authentication against the peer certificates using the given bundle and
// authorizer. The wrapped callback will be passed the verified chains.
// Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
func WrapVerifyPeerCertificate(wrapped func([][]byte, [][]*x509.Certificate) error, pool *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	if wrapped == nil {
		return VerifyPeerCertificate(pool)
	}

	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, certs, err := ParseAndVerify(raw, pool)
		if err != nil {
			return err
		}

		return wrapped(raw, certs)
	}
}

func QuicsecVerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	authLogger := log.LoggerLgr.WithName(log.ConstAuthManager)
	authLogger.V(log.DebugLevel).Info("verify peer certificate function called")

	if len(rawCerts) != 1 {
		return fmt.Errorf("auth: required exactly one peer certificate")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])

	if err != nil {
		return fmt.Errorf("auth: failed to parse peer certificate: %v", err)
	}

	for _, uri := range cert.URIs {
		rv := identity.VerifyIdentity(uri.String())
		if rv {
			authLogger.Info("verify peer certificate", "authorized", "yes", "URI", uri.String())
			return nil
		} else {
			authLogger.Info("verify peer certificate", "authorized", "no", "URI", uri.String())
		}
	}

	return fmt.Errorf("auth: No valid spiffe ID was found =(")
}
