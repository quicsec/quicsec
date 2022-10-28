// ref: https://gist.github.com/Boerworz/b683e46ae0761056a636
package log

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

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

// ref: caddyserver modules/caddyhttp/marshalers.go
// LoggableHTTPRequest makes an HTTP request loggable with zap.Object().
type LoggableHTTPRequest struct {
	*http.Request
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (r LoggableHTTPRequest) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		port = ""
	}
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
	enc.AddUint16("version", t.Version)
	enc.AddUint16("cipher_suite", t.CipherSuite)
	enc.AddString("proto", t.NegotiatedProtocol)
	enc.AddString("server_name", t.ServerName)
	if len(t.PeerCertificates) > 0 {
		enc.AddString("client_common_name", t.PeerCertificates[0].Subject.CommonName)
		enc.AddString("client_serial", t.PeerCertificates[0].SerialNumber.String())
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
		logger := LoggerRequest.Named("log.access.http")
		defer logger.Sync()

		loggableReq := zap.Object("request", LoggableHTTPRequest{
			Request: r,
		})
		accLog := logger.With(loggableReq)
		log := accLog.Info

		lrw := NewLoggingResponseWriter(w)
		wrappedHandler.ServeHTTP(lrw, r)

		duration := time.Since(start)

		log("handled request",
			zap.Duration("duration", duration),
			zap.Int("size", lrw.size),
			zap.Int("status", lrw.statusCode),
			zap.Object("resp_headers", LoggableHTTPHeader{
				Header: w.Header(),
			}),
		)
	})
}
