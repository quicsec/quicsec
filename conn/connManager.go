package conn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/quicsec/quicsec/auth"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations/httplog"
	"github.com/quicsec/quicsec/operations/log"

	"github.com/quicsec/quicsec/filters"

	ops "github.com/quicsec/quicsec/operations"
)

var roundTripper *http3.RoundTripper
var once sync.Once

func getRoundTripper() *http3.RoundTripper {
	once.Do(func() {
		roundTripper = &http3.RoundTripper{}
	})

	return roundTripper
}

func ListenAndServe(addr string, handler http.Handler) error {
	// Load certs
	var err error

	// init logger, preshared dump and tracers (metrics and qlog)
	keyLog, opsTracer := ops.OperationsInit()
	connLogger := log.LoggerLgr.WithName(log.ConstConnManager)
	config.SetServerSideFlag(true)
	connLogger.Info("ListenAndServe() initialization")

	tlsConfig := &tls.Config{
		KeyLogWriter:       keyLog,
		InsecureSkipVerify: true,
	}

	if config.GetMtlsEnable() {
		connLogger.V(log.DebugLevel).Info("mTLS enabled by configuration during start")
	} else {
		connLogger.V(log.DebugLevel).Info("mTLS disabled by configuration during start")
	}

	tlsConfig.ClientAuth = tls.RequestClientCert
	tlsConfig.VerifyPeerCertificate = auth.WrapVerifyPeerCertificate(auth.CustomVerifyPeerCertificate)

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

	filterChain := &filters.FilterChain{}

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request, ) {
		filterChain.Apply(w, r, handler.ServeHTTP)
	})

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
		Handler:    httplog.WrapHandlerWithLogging(finalHandler),
		QuicConfig: quicConf,
	}

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			quicServer.SetQuicHeaders(w.Header())
			finalHandler.ServeHTTP(w, r)
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
	start := time.Now()
	var err error
	var client *http.Client

	// init logger, preshared dump and tracers (metrics and qlog)
	keyLog, opsTracer := ops.OperationsInit()

	connLogger := log.LoggerLgr.WithName(log.ConstConnManager)
	identityLogger := log.LoggerLgr.WithName(log.ConstIdentityManager)
	config.SetServerSideFlag(false)

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
		NextProtos:         []string{http3.NextProtoH3},
	}

	if config.GetMtlsEnable() {
		connLogger.V(log.DebugLevel).Info("mTLS enabled by configuration during start")
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = auth.WrapVerifyPeerCertificate(auth.CustomVerifyPeerCertificate)
	} else {
		connLogger.V(log.DebugLevel).Info("mTLS disabled by configuration during start")
		if !config.GetInsecureSkipVerify() {
			// even if mTLS is disable, we need to validate if the
			// cert from the server cert is valid agains the CA pool
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyPeerCertificate = auth.WrapVerifyPeerCertificate(nil)
		}
	}

	quicConf := &quic.Config{
		Tracer:         opsTracer,
		MaxIdleTimeout: 500 * time.Millisecond,
	}

	getRoundTripper().TLSClientConfig = tlsConfig
	getRoundTripper().QuicConfig = quicConf

	elapsed := time.Since(start).Seconds()
	connLogger.Info("Connection setup time for requesting", "setup_time", elapsed)

	start = time.Now()
	epAddrs, err := GetAllEpAddresses(req.URL.Hostname())
	elapsed = time.Since(start).Seconds()
	connLogger.Info("DNS lookup time for requesting", "dns_lookup_time", elapsed)

	if err != nil {
		// HTTPS lookup failed doing an A lookup instead
		connLogger.V(log.DebugLevel).Info("HTTPS lookup failed... Doing an A lookup instead...")
		hostAddr, err := GetEpAddress(req.URL.Hostname())

		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed")
		}

		epAddrs = append(epAddrs, hostAddr+":"+req.URL.Port())
	}

	var resp *http.Response

	for _, ep := range epAddrs {
		start = time.Now()

		getRoundTripper().Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			conn, err := quic.DialAddrEarlyContext(context.Background(), ep, tlsConfig, quicConf)

			if err != nil {
				return nil, err
			}
			// return the QUIC connection
			return conn, nil
		}
		client = &http.Client{
			Transport: httplog.LoggingRoundTripper{Base: getRoundTripper()},
			//[TODO]  when redirectiong we can customize headers
			// CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 	if req.Response.StatusCode == http.StatusTemporaryRedirect {
			// 	}
			// 	return nil
			// },
		}

		identityLogger.V(log.DebugLevel).Info("send client request")
		resp, err = client.Do(req.WithContext(context.Background()))

		if err != nil {
			elapsed = time.Since(start).Seconds()
			connLogger.Info("Trying address failed", "address", ep, "failed_req_time", elapsed)

			continue
		}
		elapsed = time.Since(start).Seconds()
		connLogger.Info("Trying address succeed", "address", ep, "success_req_time", elapsed)
		break
	}

	if resp == nil {
		return nil, fmt.Errorf("failed to connect to any IP address")
	}

	return resp, err
}
