// ref: https://gist.github.com/Boerworz/b683e46ae0761056a636
package httplog

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	//"github.com/quicsec/quicsec/operations"

	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/identity"
	"github.com/quicsec/quicsec/operations"
	"github.com/quicsec/quicsec/operations/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// our http.ResponseWriter implementation
type loggingResponseWriter struct {
	http.ResponseWriter // compose original http.ResponseWriter
	statusCode          int
	size                int
}

func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b) // write response using original http.ResponseWriter
	r.size += size                         // capture size
	return size, err
}

func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.statusCode = statusCode                // capture status code
	r.ResponseWriter.WriteHeader(statusCode) // write status code using original http.ResponseWriter
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	// WriteHeader(int) is not called if our response implicitly returns 200 OK, so
	// we default to that status code.
	return &loggingResponseWriter{w, http.StatusOK, 0}
}

type LoggableHTTPRequestClient struct {
	*http.Request
}

// ref: caddyserver modules/caddyhttp/marshalers.go
// LoggableHTTPRequest makes an HTTP request loggable with zap.Object().
type LoggableHTTPRequest struct {
	*http.Request
}

// This type implements the http.RoundTripper interface
type LoggingRoundTripper struct {
	Base http.RoundTripper
}

func (lrt LoggingRoundTripper) RoundTrip(r *http.Request) (res *http.Response, err error) {
	start := time.Now()
	logger := log.LoggerRequest.Named("quicsec.log.access.http.client")
	defer logger.Sync()

	loggableReq := zap.Object("request", LoggableHTTPRequestClient{
		Request: r,
	})
	accLog := logger.With(loggableReq)
	log := accLog.Info

	// Send the request, get the response
	res, err = lrt.Base.RoundTrip(r)

	duration := time.Since(start)

	if err != nil {
		log("handled request",
			zap.Duration("duration", duration),
			zap.String("error", err.Error()),
		)
	} else {
		size := 0
		if res.ContentLength > 0 {
			size = int(res.ContentLength)
		}

		// Prometheus metrics for HTTP
		if len(res.TLS.PeerCertificates) > 0 {
			serverId, err := identity.IDFromCert(res.TLS.PeerCertificates[0])
			if err == nil {
				operations.HttpRequestsPathIdClient.WithLabelValues(config.GetIdentity().String(), serverId.String(), r.Host, r.Method, r.URL.RequestURI(), strconv.Itoa(res.StatusCode)).Inc()
				operations.HTTPHistogramNetworkLatencyId.WithLabelValues(config.GetIdentity().String(), serverId.String()).Observe(duration.Seconds())
			}
		}

		log("handled request",
			zap.Duration("duration", duration),
			zap.Int("size", size),
			zap.Int("response_code", res.StatusCode),
			zap.Object("tls", LoggableTLSConnState(*res.TLS)),
			// zap.Object("resp_headers", LoggableHTTPHeader{
			// 	Header: res.Header,
			// }),
		)
	}

	return res, err
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (r LoggableHTTPRequestClient) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	ip, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		ip = r.Host
		port = ""
	}
	enc.AddString("myId", config.GetIdentity().String())
	enc.AddString("remote_ip", ip)
	enc.AddString("remote_port", port)
	enc.AddString("proto", r.Proto)
	enc.AddString("method", r.Method)
	enc.AddString("host", r.Host)
	enc.AddString("uri", r.URL.RequestURI())
	enc.AddObject("headers", LoggableHTTPHeader{
		Header: r.Header,
	})

	if r.TLS != nil {
		enc.AddObject("tls", LoggableTLSConnState(*r.TLS))
	}
	return nil
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (r LoggableHTTPRequest) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		port = ""
	}
	enc.AddString("myId", config.GetIdentity().String())
	enc.AddString("remote_ip", ip)
	enc.AddString("remote_port", port)
	enc.AddString("proto", r.Proto)
	enc.AddString("method", r.Method)
	enc.AddString("host", r.Host)
	enc.AddString("uri", r.RequestURI)
	enc.AddObject("headers", LoggableHTTPHeader{
		Header: r.Header,
	})
	if r.TLS != nil {
		enc.AddObject("tls", LoggableTLSConnState(*r.TLS))
	}
	return nil
}

// LoggableTLSConnState makes a TLS connection state loggable with zap.Object().
type LoggableTLSConnState tls.ConnectionState

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (t LoggableTLSConnState) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("resumed", t.DidResume)
	// enc.AddUint16("version", t.Version)
	// enc.AddUint16("cipher_suite", t.CipherSuite)
	enc.AddString("proto", t.NegotiatedProtocol)
	enc.AddString("server_name", t.ServerName)
	if len(t.PeerCertificates) > 0 {
		// enc.AddString("client_common_name", t.PeerCertificates[0].Subject.CommonName)
		// enc.AddString("client_serial", t.PeerCertificates[0].SerialNumber.String())

		serverId, err := identity.IDFromCert(t.PeerCertificates[0])
		if err == nil {
			if config.GetServerSideFlag() {
				enc.AddString("dowstreamId", serverId.String())
			} else {
				enc.AddString("upstreamId", serverId.String())
			}
		}

	}
	return nil
}

// LoggableHTTPHeader makes an HTTP header loggable with zap.Object().
// Headers with potentially sensitive information (Cookie, Set-Cookie,
// Authorization, and Proxy-Authorization) are logged with empty values.
type LoggableHTTPHeader struct {
	http.Header

	ShouldLogCredentials bool
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (h LoggableHTTPHeader) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if h.Header == nil {
		return nil
	}
	for key, val := range h.Header {
		if !h.ShouldLogCredentials {
			switch strings.ToLower(key) {
			case "cookie", "set-cookie", "authorization", "proxy-authorization":
				val = []string{}
			}
		}
		enc.AddArray(key, LoggableStringArray(val))
	}
	return nil
}

// LoggableStringArray makes a slice of strings marshalable for logging.
type LoggableStringArray []string

// MarshalLogArray satisfies the zapcore.ArrayMarshaler interface.
func (sa LoggableStringArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if sa == nil {
		return nil
	}
	for _, s := range sa {
		enc.AppendString(s)
	}
	return nil
}

func WrapHandlerWithLogging(wrappedHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger := log.LoggerRequest.Named("quicsec.log.access.http.server")
		defer logger.Sync()

		loggableReq := zap.Object("request", LoggableHTTPRequest{
			Request: r,
		})
		accLog := logger.With(loggableReq)
		log := accLog.Info

		lrw := NewLoggingResponseWriter(w)
		wrappedHandler.ServeHTTP(lrw, r)

		duration := time.Since(start)

		// Prometheus metrics for HTTP
		if len(r.TLS.PeerCertificates) > 0 {
			serverId, err := identity.IDFromCert(r.TLS.PeerCertificates[0])
			if err == nil {
				operations.HttpRequestsPathIdServer.WithLabelValues(config.GetIdentity().String(), serverId.String(), r.Host, r.Method, r.RequestURI, strconv.Itoa(lrw.statusCode)).Inc()
				operations.HTTPHistogramAppProcessId.WithLabelValues(config.GetIdentity().String(), serverId.String()).Observe(duration.Seconds())
			}
		}

		log("handled request",
			zap.Duration("duration", duration),
			zap.Int("size", lrw.size),
			zap.Int("response_code", lrw.statusCode),
			zap.Object("resp_headers", LoggableHTTPHeader{
				Header: w.Header(),
			}),
		)
	})
}
