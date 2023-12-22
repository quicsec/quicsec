package auth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations"
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

// Verify verifies an X509-SVID chain using the X.509 bundle source. It
// returns the SPIFFE ID of the X509-SVID and one or more chains back to a root
// in the bundle.
func Verify(certs []*x509.Certificate, opts ...VerifyOption) (spiffeid.ID, [][]*x509.Certificate, error) {
	authLogger := log.LoggerLgr.WithName(log.ConstConnManager)

	authLogger.V(log.DebugLevel).Info("verify X509-SVID chain using the X.509 bundle source")

	if !config.GetMtlsEnable() {
		if len(certs) == 0 {
			authLogger.V(log.DebugLevel).Info("mtls disabled, skip X509-SVID verification. Certificate not supplied by peer")
		} else {
			authLogger.V(log.DebugLevel).Info("mtls disabled, skip X509-SVID verification. Certificate supplied by peer")
		}
		return spiffeid.ID{}, nil, nil
	}

	myPool, err := identity.GetCertPool()
	if err != nil {
		authLogger.Error(err, "failed to get system cert pool")
	}

	vConfig := &verifyConfig{}
	for _, opt := range opts {
		opt.apply(vConfig)
	}

	switch {
	case len(certs) == 0:
		authLogger.V(log.DebugLevel).Info("certificate not supplied by peer")
		if config.GetStarPolicyEnable() {
			authLogger.V(log.DebugLevel).Info("Policy '*' (STAR) is enabled")
			starId, err := spiffeid.FromString("spiffe://*")
			if err != nil {
				return spiffeid.ID{}, nil, errors.New("failed to create wildcard spiffe id for '*'")
			}
			return starId, nil, nil
		} else {
			return spiffeid.ID{}, nil, errors.New("empty certificates chain")
		}
	case myPool == nil:
		return spiffeid.ID{}, nil, errors.New("pool is required")
	}

	leaf := certs[0]
	id, err := identity.IDFromCert(leaf)
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
		Roots:         myPool,
		Intermediates: NewCertPool(certs[1:]),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   vConfig.now,
	})
	if err != nil {
		return id, nil, fmt.Errorf("auth: could not verify leaf certificate: %w", err)
	}

	return id, verifiedChains, nil
}

// ParseAndVerify parses and verifies an X509-SVID chain using the X.509
// bundle source. It returns the SPIFFE ID of the X509-SVID and one or more
// chains back to a root in the bundle.
func ParseAndVerify(rawCerts [][]byte) (spiffeid.ID, [][]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return spiffeid.ID{}, nil, fmt.Errorf("unable to parse certificate: %w", err)

		}
		certs = append(certs, cert)
	}
	return Verify(certs)
}

// VerifyPeerCertificate returns a VerifyPeerCertificate callback for
// tls.Config. It uses the given bundle source and authorizer to verify and
// authorize X509-SVIDs provided by peers during the TLS handshake.
func VerifyPeerCertificate() func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, _, err := ParseAndVerify(raw)

		return err
	}
}

// WrapVerifyPeerCertificate wraps a VeriyPeerCertificate callback, performing
// SPIFFE authentication against the peer certificates using the given bundle and
// authorizer. The wrapped callback will be passed the verified chains.
// Note: TLS clients must set `InsecureSkipVerify` when doing SPIFFE authentication to disable hostname verification.
func WrapVerifyPeerCertificate(wrapped func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	if wrapped == nil {
		return VerifyPeerCertificate()
	}

	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, certs, err := ParseAndVerify(raw)
		if err != nil {
			return err
		}

		return wrapped(raw, certs)
	}
}

func CustomVerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	authLogger := log.LoggerLgr.WithName(log.ConstAuthManager)
	authLogger.V(log.DebugLevel).Info("verify identity of peer certificate")

	if !config.GetMtlsEnable() {
		authLogger.V(log.DebugLevel).Info("mtls disabled, skip identity verification")
		if len(rawCerts) > 0 {
			certLog, err := x509.ParseCertificate(rawCerts[0])
			if err == nil {
				for _, uri := range certLog.URIs {
					authLogger.V(log.DebugLevel).Info("peer certificate", "URI:", uri.String())
				}
			}
		}
		return nil
	}

	if len(rawCerts) != 1 {
		return fmt.Errorf("auth: required exactly one peer certificate")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])

	if err != nil {
		return fmt.Errorf("auth: failed to parse peer certificate: %v", err)
	}

	for _, uri := range cert.URIs {
		rv := identity.AllowedIdentity(uri.String())
		if rv {
			authLogger.Info("verify peer certificate", "authorized", "yes", "URI", uri.String())
			if config.GetMetricsEnabled() {
				if config.GetServerSideFlag() {
					operations.AuthzConnectiontServerId.WithLabelValues(config.GetIdentity().String(), uri.String(), "authorized").Inc()
				} else {
					operations.AuthzConnectiontClientId.WithLabelValues(config.GetIdentity().String(), uri.String(), "authorized").Inc()
				}
			}
			return nil
		} else {
			if config.GetStarPolicyEnable() {
				authLogger.V(log.DebugLevel).Info("Creating a wildcard identity for policy '*' (STAR) due to the absence of a peer certificate.")
				authLogger.Info("verify peer wildcard", "authorized", "yes", "URI", "spiffe://*")

				//if config.GetServerSideFlag() {
					// increment metrics for star authz
				//}
				return nil
			} else {
				if config.GetMetricsEnabled() {
					if config.GetServerSideFlag() {
						operations.AuthzConnectiontServerId.WithLabelValues(config.GetIdentity().String(), uri.String(), "unauthorized").Inc()
					} else {
						operations.AuthzConnectiontClientId.WithLabelValues(config.GetIdentity().String(), uri.String(), "unauthorized").Inc()
					}
				}
				authLogger.Info("verify peer certificate", "authorized", "no", "URI", uri.String())
			}
		}
	}

	return fmt.Errorf("auth: No valid spiffe ID was found =(")
}
