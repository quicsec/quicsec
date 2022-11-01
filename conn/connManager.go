package conn

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"

	"github.com/quicsec/quicsec/auth"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations/log"

	ops "github.com/quicsec/quicsec/operations"
)

func ListenAndServe(addr string, handler http.Handler) error {
	// Load certs
	var err error

	// init logger, preshared dump and tracers (metrics and qlog)
	keyLog, opsTracer := ops.OperationsInit()
	connLogger := log.LoggerLgr.WithName(log.ConstConnManager)

	connLogger.Info("ListenAndServe() initialization")

	tlsConfig := &tls.Config{
		KeyLogWriter:       keyLog,
		InsecureSkipVerify: true,
	}

	if config.GetMtlsEnable() {
		connLogger.V(log.DebugLevel).Info("mTLS enabled by configuration")
		tlsConfig.VerifyPeerCertificate = auth.WrapVerifyPeerCertificate(auth.CustomVerifyPeerCertificate)
		tlsConfig.ClientAuth = tls.RequireAnyClientCert
	} else {
		connLogger.V(log.DebugLevel).Info("mTLS disabled by configuration")
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	connLogger.V(log.DebugLevel).Info("try to bind address for tcp/udp", "addr", addr)

	// Open the listeners
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		connLogger.Error(err, "failed to resolve the address of UDP end point")
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		connLogger.Error(err, "failed to Listen at UDP address")
		return err
	}
	defer udpConn.Close()

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		connLogger.Error(err, "failed to resolve the address of TCP end point")
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		connLogger.Error(err, "failed to Listen at TCP address")
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

	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {

		cert, err := identity.GetCert()

		if err != nil {
			//operations.ProbeError(operations.ConstIdentityManager, err)
			return nil, err
		}

		return cert, nil
	}

	// Start the servers
	quicServer := &http3.Server{
		TLSConfig:  tlsConfig,
		Handler:    log.WrapHandlerWithLogging(handler),
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
	keyLog, opsTracer := ops.OperationsInit()

	connLogger := log.LoggerLgr.WithName(log.ConstConnManager)
	identityLogger := log.LoggerLgr.WithName(log.ConstIdentityManager)

	connLogger.Info("client.Do() initialization")

	idCert, err := identity.GetCert()

	if err != nil {
		identityLogger.Error(err, "failed to fetch identity for client")
		return nil, err
	}

	identityLogger.V(log.DebugLevel).Info("identity successfully obtained for the client")

	certs := make([]tls.Certificate, 1)
	certs[0] = *idCert

	tlsConfig := &tls.Config{
		Certificates:       certs,
		InsecureSkipVerify: config.GetInsecureSkipVerify(),
		KeyLogWriter:       keyLog,
	}

	if config.GetMtlsEnable() {
		connLogger.V(log.DebugLevel).Info("mTLS enabled by configuration")
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = auth.WrapVerifyPeerCertificate(auth.CustomVerifyPeerCertificate)
	} else {

		if !config.GetInsecureSkipVerify() {
			// even if mTLS is disable, we need to validate if the
			// cert from the server cert is valid agains the CA pool
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyPeerCertificate = auth.WrapVerifyPeerCertificate(nil)
		}
	}

	quicConf := &quic.Config{
		Tracer: opsTracer,
	}

	roudTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		QuicConfig:      quicConf,
	}

	client = &http.Client{
		Transport: log.LoggingRoundTripper{Base: roudTripper},
	}

	identityLogger.V(log.DebugLevel).Info("send client request")
	resp, err := client.Do(req)

	if err != nil {
		connLogger.Error(err, "failed client.Do()")
	}

	return resp, err
}
