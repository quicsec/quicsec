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
	"github.com/quicsec/quicsec/http/filters"
	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations/httplog"
	"github.com/quicsec/quicsec/operations/log"

	ops "github.com/quicsec/quicsec/operations"
)

var roundTripper *http3.RoundTripper
var http1Handle *http.Transport
var once sync.Once

func getRoundTripper() *http3.RoundTripper {
	once.Do(func() {
		roundTripper = &http3.RoundTripper{}
	})

	return roundTripper
}

func getHTTPTransport() *http.Transport {
	once.Do(func() {
		http1Handle = &http.Transport{}
	})

	return http1Handle
}

func ListenAndServe(addr string, handler http.Handler) error {
	// Load certs
	var err error

	// init logger, preshared dump and tracers (metrics and qlog)
	keyLog, opsTracer := ops.OperationsInit()
	connLogger := log.LoggerLgr.WithName(log.ConstConnManager)
	config.SetServerSideFlag(true)
	connLogger.V(log.DebugLevel).Info("ListenAndServe() initialization")

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

	/* configure filter chain */
	filterChain := &filters.FilterChain{
		Filters: []filters.Filters{
			filters.NewCorazaFilter("/home/vagrant/go/src/github.com/quicsec/quicsec/http/filters/default.config"),
			filters.NewExtAuthFilter("http://localhost:8181/v1/data/httpapi/authz"),
		},
	}

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	var qErr chan error
	var hErr chan error
	var quicServer *http3.Server
	var httpServer *http.Server

	qErr = make(chan error)
	hErr = make(chan error)

	if config.GetLocalOnlyH1() {
		connLogger.V(log.DebugLevel).Info("Listen only protocol HTTP/1.1 (TCP)", "addr", tcpAddr)
		httpServer = &http.Server{
			Handler: httplog.WrapHandlerWithLogging(finalHandler),
		}

	} else {
		quicServer = &http3.Server{
			TLSConfig:  tlsConfig,
			Handler:    httplog.WrapHandlerWithLogging(finalHandler),
			QuicConfig: quicConf,
		}

		go func() {
			qErr <- quicServer.Serve(udpConn)
		}()

		// Add Alt-Svc header if supports H3
		var AltSvcMiddleware = func(next http.Handler, altSvc *http3.Server) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				altSvc.SetQuicHeaders(w.Header())
				next.ServeHTTP(w, r)
			})
		}

		httpServer = &http.Server{
			Handler: AltSvcMiddleware(httplog.WrapHandlerWithLogging(finalHandler), quicServer),
		}
		connLogger.V(log.DebugLevel).Info("Listen both protocol HTTP/1.1 (TCP) and HTTP/3 (UDP)", "addr", tcpAddr)
	}

	go func() {
		hErr <- httpServer.Serve(tlsConn)
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

	connLogger.V(log.DebugLevel).Info("client.Do() initialization")

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

	elapsed := time.Since(start).Seconds()
	connLogger.V(log.DebugLevel).Info("Connection setup time for requesting", "setup_time", elapsed)

	start = time.Now()
	dst := req.URL.Hostname()

	// It's a domain name
	var epAddrs []string
	if net.ParseIP(dst) == nil {
		epAddrs, err = GetAllEpAddresses(dst)
		elapsed = time.Since(start).Seconds()
		connLogger.V(log.DebugLevel).Info("DNS lookup time for requesting", "dns_lookup_time", elapsed)

		if err != nil {
			// HTTPS lookup failed doing an A lookup instead
			connLogger.V(log.DebugLevel).Info("HTTPS lookup failed... Doing an A lookup instead...")
			hostAddr, err := GetEpAddress(dst)
			if err != nil {
				return nil, fmt.Errorf("DNS resolution failed")
			}

			epAddrs = append(epAddrs, hostAddr+":"+req.URL.Port())
		}
	} else { // Its an IP address
		epAddrs = append(epAddrs, dst+":"+req.URL.Port())
	}

	var resp *http.Response

	for _, ep := range epAddrs {
		start = time.Now()
		if config.GetLocalOnlyH1() {
			getHTTPTransport().TLSClientConfig = tlsConfig

			client = &http.Client{
				Transport: httplog.LoggingRoundTripper{Base: getHTTPTransport()},
			}
		} else { // Quic configuration
			quicConf := &quic.Config{
				Tracer:         opsTracer,
				MaxIdleTimeout: 500 * time.Millisecond,
			}

			getRoundTripper().TLSClientConfig = tlsConfig
			getRoundTripper().QuicConfig = quicConf

			getRoundTripper().Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := quic.DialAddrEarlyContext(context.Background(), ep, tlsConfig, quicConf)

				if err != nil {
					return nil, err
				}
				// return the QUIC connection
				return conn, nil
			}
			tlsConfig.NextProtos = []string{http3.NextProtoH3}
			client = &http.Client{
				Transport: httplog.LoggingRoundTripper{Base: getRoundTripper()},
			}
		}

		identityLogger.V(log.DebugLevel).Info("send client request")
		resp, err = client.Do(req.WithContext(context.Background()))

		if err != nil {
			elapsed = time.Since(start).Seconds()
			connLogger.V(log.DebugLevel).Info("Trying address failed", "address", ep, "failed_req_time", elapsed)

			continue
		}
		elapsed = time.Since(start).Seconds()
		connLogger.V(log.DebugLevel).Info("Trying address succeed", "address", ep, "success_req_time", elapsed)
		break
	}

	if resp == nil {
		return nil, fmt.Errorf("failed to connect to any IP address")
	}

	return resp, err
}
