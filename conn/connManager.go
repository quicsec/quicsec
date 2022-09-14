package conn

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"net"
	"crypto/tls"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"

	"github.com/quicsec/quicsec/utils"
	"github.com/quicsec/quicsec/auth"
	"github.com/quicsec/quicsec/identity"
)

func ListenAndServe(addr string, handler http.Handler) error {
	// Load certs
	var err error
	enableQlog := true// configurable

	idCert, err := identity.GetIndentityCert()

	if err != nil {
		return err
	}

	certs := make([]tls.Certificate, 1)
	certs[0] = *idCert
	
	tlsConfig := &tls.Config{
		Certificates: certs,
		VerifyPeerCertificate: auth.QuicsecVerifyPeerCertificate,
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

	quicConf := &quic.Config{}

	if enableQlog {
		quicConf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("qlog/server_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	// Start the servers
	quicServer := &http3.Server{
		TLSConfig: tlsConfig,
		Handler: handler,
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