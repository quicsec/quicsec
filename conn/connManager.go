package conn

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"

	"github.com/quicsec/quicsec/auth"
	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations"
)

func ListenAndServe(addr string, handler http.Handler) error {
	// Load certs
	var err error

	// init logger, preshared dump and tracers (metrics and qlog)
	logger, keyLog, opsTracer := operations.OperationsInit()

	logger.Debugf("Quicsec ListenAndServe initialization")

	idCert, err := identity.GetIndentityCert()

	if err != nil {
		operations.ProbeError(operations.ConstIdentityManager, err)
		return err
	}

	certs := make([]tls.Certificate, 1)
	certs[0] = *idCert

	pool, err := x509.SystemCertPool()

	if err != nil {
		log.Fatal(err)
	}

	identity.AddRootCA(pool)

	tlsConfig := &tls.Config{
		Certificates:          certs,
		VerifyPeerCertificate: auth.QuicsecVerifyPeerCertificate,
		KeyLogWriter:          keyLog,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		InsecureSkipVerify:    true,
		ClientCAs:             pool,
	}

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, tlsConfig)
	defer tlsConn.Close()

	if handler == nil {
		handler = http.DefaultServeMux
	}

	quicConf := &quic.Config{
		Tracer: opsTracer,
	}

	// Start the servers
	quicServer := &http3.Server{
		TLSConfig:  tlsConfig,
		Handler:    handler,
		QuicConfig: quicConf,
	}

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			quicServer.SetQuicHeaders(w.Header())
			handler.ServeHTTP(w, r)
		}),
	}

	hErr := make(chan error)
	qErr := make(chan error)
	go func() {
		hErr <- httpServer.Serve(tlsConn)
	}()
	go func() {
		qErr <- quicServer.Serve(udpConn)
	}()

	select {
	case err := <-hErr:
		quicServer.Close()
		return err
	case err := <-qErr:
		// Cannot close the HTTP server or wait for requests to complete properly :/
		return err
	}
}

func Do(req *http.Request) (*http.Response, error) {
	var err error
	var client *http.Client

	// init logger, preshared dump and tracers (metrics and qlog)
	logger, keyLog, opsTracer := operations.OperationsInit()

	logger.Debugf("Quicsec client.Do initialization")

	idCert, err := identity.GetIndentityCert()

	if err != nil {
		operations.ProbeError(operations.ConstIdentityManager, err)
		return nil, err
	}

	certs := make([]tls.Certificate, 1)
	certs[0] = *idCert

	pool, err := x509.SystemCertPool()

	if err != nil {
		log.Fatal(err)
	}

	identity.AddRootCA(pool)

	tlsConfig := &tls.Config{
		Certificates:       certs,
		RootCAs:            pool,
		InsecureSkipVerify: false,
		KeyLogWriter:       keyLog,
	}

	quicConf := &quic.Config{
		Tracer: opsTracer,
	}

	roudTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		QuicConfig:      quicConf,
	}

	client = &http.Client{
		Transport: roudTripper,
	}

	resp, err := client.Do(req)

	return resp, err
}
