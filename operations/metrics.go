// ref: https://github.com/libp2p/go-libp2p/blob/master/p2p/transport/quic/tracer_metrics.go
package operations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/operations/log"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	bytesTransferred   		*prometheus.CounterVec
	packetsTransferred 		*prometheus.CounterVec
	newConns           		*prometheus.CounterVec
	closedConns        		*prometheus.CounterVec
	sentPackets        		*prometheus.CounterVec
	rcvdPackets        		*prometheus.CounterVec
	bufferedPackets    		*prometheus.CounterVec
	droppedPackets     		*prometheus.CounterVec
	lostPackets        		*prometheus.CounterVec
	connErrors         		*prometheus.CounterVec
	HttpRequestsPath		*prometheus.CounterVec
	HttpRequestsStatus		*prometheus.CounterVec

	HTTPHistogramAppProcess = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:      "http_request_application_process_latency",
			Help:      "The application latency to process a HTTP request",
			Buckets: prometheus.ExponentialBuckets(0.001, 1.25, 40), // 1ms to ~6000ms
		})

	HTTPHistogramNetworkLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:      "http_request_network_latency",
			Help:      "The network latency between the request and the response",
			Buckets: prometheus.ExponentialBuckets(0.001, 1.25, 40), // 1ms to ~6000ms
		})	
)

type aggregatingCollector struct {
	mutex sync.Mutex

	// conn ID map
	conns map[string]*metricsConnTracer

	connDurations prometheus.Histogram
}

func newAggregatingCollector() *aggregatingCollector {
	return &aggregatingCollector{
		conns: make(map[string]*metricsConnTracer),
		connDurations: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "quic_connection_duration",
			Help:    "Connection Duration",
			Buckets: prometheus.ExponentialBuckets(1, 1.5, 40), // 1s to ~12 weeks
		}),
	}
}

var _ prometheus.Collector = &aggregatingCollector{}

func (c *aggregatingCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.connDurations.Desc()
}

func (c *aggregatingCollector) Collect(metrics chan<- prometheus.Metric) {
	now := time.Now()
	c.mutex.Lock()
	for _, conn := range c.conns {
		c.connDurations.Observe(now.Sub(conn.startTime).Seconds())
	}
	c.mutex.Unlock()
	metrics <- c.connDurations
}

func (c *aggregatingCollector) AddConn(id string, t *metricsConnTracer) {
	c.mutex.Lock()
	c.conns[id] = t
	c.mutex.Unlock()
}

func (c *aggregatingCollector) RemoveConn(id string) {
	c.mutex.Lock()
	delete(c.conns, id)
	c.mutex.Unlock()
}

var collector *aggregatingCollector

type MetricsTracer struct {
	logging.NullTracer
}

var _ logging.Tracer = &MetricsTracer{}

type metricsConnTracer struct {
	logging.NullConnectionTracer

	perspective       logging.Perspective
	startTime         time.Time
	connID            logging.ConnectionID
	handshakeComplete bool

	mutex              sync.Mutex
	numRTTMeasurements int
	rtt                time.Duration
}

var _ logging.ConnectionTracer = &metricsConnTracer{}

func runPrometheusHTTP(address string) {
	prometheusBind := address
	metrics_path := "/metrics"
	http_url := "http://" + prometheusBind + metrics_path

	log.LoggerLgr.WithName(log.ConstOperationsManager).V(log.DebugLevel).Info("Prometheus metrics avaiable", "url", http_url)

	http.Handle(metrics_path, promhttp.Handler())
	err := http.ListenAndServe(prometheusBind, nil)
	if err != nil {
		log.LoggerLgr.WithName(log.ConstOperationsManager).Error(err, "ListenAndServe failed for prometheus")
	}
}

// metricsInit start tracing the metrics using prometheus
func metricsInit() {
	const (
		direction = "direction"
		encLevel  = "encryption_level"
	)

	closedConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_connections_closed_total",
			Help: "closed QUIC connection",
		},
		[]string{direction},
	)
	prometheus.MustRegister(closedConns)
	newConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_connections_new_total",
			Help: "new QUIC connection",
		},
		[]string{direction, "handshake_successful"},
	)
	prometheus.MustRegister(newConns)
	bytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_transferred_bytes",
			Help: "QUIC bytes transferred",
		},
		[]string{direction},
	)
	prometheus.MustRegister(bytesTransferred)
	packetsTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_transferred_packets_total",
			Help: "QUIC packets transferred",
		},
		[]string{direction},
	)
	prometheus.MustRegister(packetsTransferred)
	sentPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_packets_sent_total",
			Help: "QUIC packets sent",
		},
		[]string{encLevel},
	)
	prometheus.MustRegister(sentPackets)
	rcvdPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_packets_rcvd_total",
			Help: "QUIC packets received",
		},
		[]string{encLevel},
	)
	prometheus.MustRegister(rcvdPackets)
	bufferedPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_packets_buffered_total",
			Help: "Buffered packets",
		},
		[]string{"packet_type"},
	)
	prometheus.MustRegister(bufferedPackets)
	droppedPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_packets_dropped_total",
			Help: "Dropped packets",
		},
		[]string{"packet_type", "reason"},
	)
	prometheus.MustRegister(droppedPackets)
	connErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_connection_errors_total",
			Help: "QUIC connection errors",
		},
		[]string{"side", "error_code", "reason"},
	)
	prometheus.MustRegister(connErrors)
	lostPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_packets_lost_total",
			Help: "QUIC lost received",
		},
		[]string{encLevel, "reason"},
	)
	prometheus.MustRegister(lostPackets)
	HttpRequestsPath = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_path_counter",
			Help: "HTTP requests counter by group (method, path and status)",
		},
		[]string{"instance", "method", "path", "status"},
	)
	prometheus.MustRegister(HttpRequestsPath)
	HttpRequestsStatus = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_request_status_counter",
			Help: "HTTP requests counter only by status",
		},
		[]string{"status"},
	)
	prometheus.MustRegister(HttpRequestsStatus)

	collector = newAggregatingCollector()
	prometheus.MustRegister(collector)

	prometheus.MustRegister(HTTPHistogramAppProcess)

	prometheus.MustRegister(HTTPHistogramNetworkLatency)

	pFlag, pAddr := config.GetPrometheusHTTPConfig()
	if pFlag {
		go runPrometheusHTTP(pAddr)
	} else {
		log.LoggerLgr.WithName(log.ConstOperationsManager).V(log.DebugLevel).Info("configure QUICSEC_PROMETHEUS_BIND to access Prometheus metrics")
	}
}
func (m *MetricsTracer) TracerForConnection(_ context.Context, p logging.Perspective, connID logging.ConnectionID) logging.ConnectionTracer {
	return &metricsConnTracer{perspective: p, connID: connID}
}

// need to be implemented - quic-go/qlog has these interfaces implemented
func (m *MetricsTracer) NegotiatedVersion(chosen logging.VersionNumber, client, server []logging.VersionNumber) {
}
func (m *metricsConnTracer) AcknowledgedPacket(logging.EncryptionLevel, logging.PacketNumber) {}

func (m *metricsConnTracer) SentTransportParameters(tp *logging.TransportParameters) {}

func (m *metricsConnTracer) ReceivedTransportParameters(tp *logging.TransportParameters) {}

func (m *metricsConnTracer) RestoredTransportParameters(tp *logging.TransportParameters) {}

func (m *metricsConnTracer) UpdatedCongestionState(state logging.CongestionState) {}

func (m *metricsConnTracer) UpdatedPTOCount(value uint32) {}

func (m *metricsConnTracer) UpdatedKeyFromTLS(encLevel logging.EncryptionLevel, pers logging.Perspective) {
}
func (m *metricsConnTracer) UpdatedKey(generation logging.KeyPhase, remote bool) {}

func (m *metricsConnTracer) DroppedKey(generation logging.KeyPhase) {}

func (m *metricsConnTracer) SetLossTimer(tt logging.TimerType, encLevel logging.EncryptionLevel, timeout time.Time) {
}

func (m *metricsConnTracer) LossTimerExpired(tt logging.TimerType, encLevel logging.EncryptionLevel) {
}
func (m *metricsConnTracer) LossTimerCanceled() {}

func (m *metricsConnTracer) Debug(name, msg string) {}

// end - need to be implemented

func (m *metricsConnTracer) getDirection() string {
	if m.perspective == logging.PerspectiveClient {
		return "outgoing"
	}
	return "incoming"
}

func (m *metricsConnTracer) getEncLevel(packetType logging.PacketType) string {
	switch packetType {
	case logging.PacketType0RTT:
		return "0-RTT"
	case logging.PacketTypeInitial:
		return "Initial"
	case logging.PacketTypeHandshake:
		return "Handshake"
	case logging.PacketTypeRetry:
		return "Retry"
	case logging.PacketType1RTT:
		return "1-RTT"
	default:
		return "unknown"
	}
}

func (m *metricsConnTracer) StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
	m.startTime = time.Now()
	collector.AddConn(m.connID.String(), m)
}

func (m *metricsConnTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
	m.mutex.Lock()
	m.rtt = rttStats.SmoothedRTT()
	m.numRTTMeasurements++
	m.mutex.Unlock()
}

func (m *metricsConnTracer) SentPacket(hdr *logging.ExtendedHeader, packetSize logging.ByteCount, _ *logging.AckFrame, _ []logging.Frame) {
	bytesTransferred.WithLabelValues("sent").Add(float64(packetSize))
	sentPackets.WithLabelValues(m.getEncLevel(logging.PacketTypeFromHeader(&hdr.Header))).Inc()
	packetsTransferred.WithLabelValues("sent").Inc()
}

func (m *metricsConnTracer) ReceivedVersionNegotiationPacket(dest logging.ArbitraryLenConnectionID, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber) {
	//TODO: test the difference between libp2p to see what is hdr.ParsedLen()
	//bytesTransferred.WithLabelValues("rcvd").Add(float64(hdr.ParsedLen() + logging.ByteCount(4*len(versions))))
	rcvdPackets.WithLabelValues("Version Negotiation").Inc()
}

func (m *metricsConnTracer) ReceivedRetry(hdr *logging.Header) {
	rcvdPackets.WithLabelValues("Retry").Inc()
}

func (m *metricsConnTracer) ReceivedLongHeaderPacket(hdr *logging.ExtendedHeader, packetSize logging.ByteCount, _ []logging.Frame) {
	bytesTransferred.WithLabelValues("rcvd").Add(float64(packetSize))
	rcvdPackets.WithLabelValues(m.getEncLevel(logging.PacketTypeFromHeader(&hdr.Header))).Inc()
	packetsTransferred.WithLabelValues("rcvd").Inc()
}

func (m *metricsConnTracer) ReceivedShortHeaderPacket(hdr *logging.ShortHeader, packetSize logging.ByteCount, _ []logging.Frame) {
	bytesTransferred.WithLabelValues("rcvd").Add(float64(packetSize))
	rcvdPackets.WithLabelValues(m.getEncLevel(logging.PacketType1RTT)).Inc()
	packetsTransferred.WithLabelValues("rcvd").Inc()
}

func (m *metricsConnTracer) BufferedPacket(pt logging.PacketType) {
	bufferedPackets.WithLabelValues(m.getEncLevel(pt)).Inc()
}

func (m *metricsConnTracer) DroppedPacket(pt logging.PacketType, size logging.ByteCount, r logging.PacketDropReason) {
	bytesTransferred.WithLabelValues("rcvd").Add(float64(size))

	var reason string
	switch r {
	case logging.PacketDropKeyUnavailable:
		reason = "key_unavailable"
	case logging.PacketDropUnknownConnectionID:
		reason = "unknown_connection_id"
	case logging.PacketDropHeaderParseError:
		reason = "header_parse_error"
	case logging.PacketDropPayloadDecryptError:
		reason = "payload_decrypt_error"
	case logging.PacketDropProtocolViolation:
		reason = "protocol_violation"
	case logging.PacketDropDOSPrevention:
		reason = "dos_prevention"
	case logging.PacketDropUnsupportedVersion:
		reason = "unsupported_version"
	case logging.PacketDropUnexpectedPacket:
		reason = "unexpected_packet"
	case logging.PacketDropUnexpectedSourceConnectionID:
		reason = "unexpected_source_connection_id"
	case logging.PacketDropUnexpectedVersion:
		reason = "unexpected_version"
	case logging.PacketDropDuplicate:
		reason = "duplicate"
	default:
		reason = "unknown packet drop reason"
	}
	droppedPackets.WithLabelValues(m.getEncLevel(pt), reason).Inc()
}

func (m *metricsConnTracer) LostPacket(encLevel logging.EncryptionLevel, _ logging.PacketNumber, r logging.PacketLossReason) {
	var reason string
	switch r {
	case logging.PacketLossReorderingThreshold:
		reason = "reordering_threshold"
	case logging.PacketLossTimeThreshold:
		reason = "time_threshold"
	default:
		reason = "unknown loss reason"
	}
	lostPackets.WithLabelValues(encLevel.String(), reason).Inc()
}

func (m *metricsConnTracer) DroppedEncryptionLevel(level logging.EncryptionLevel) {
	if level == logging.EncryptionHandshake {
		m.handleHandshakeComplete()
	}
}

func (m *metricsConnTracer) handleHandshakeComplete() {
	m.handshakeComplete = true
	newConns.WithLabelValues(m.getDirection(), "true").Inc()
}

func (m *metricsConnTracer) Close() {
	if m.handshakeComplete {
		closedConns.WithLabelValues(m.getDirection()).Inc()
	} else {
		newConns.WithLabelValues(m.getDirection(), "false").Inc()
	}

	collector.RemoveConn(m.connID.String())
}

func (m *metricsConnTracer) ClosedConnection(e error) {
	var (
		applicationErr      *quic.ApplicationError
		transportErr        *quic.TransportError
		statelessResetErr   *quic.StatelessResetError
		vnErr               *quic.VersionNegotiationError
		idleTimeoutErr      *quic.IdleTimeoutError
		handshakeTimeoutErr *quic.HandshakeTimeoutError
		remote              bool
		desc                string
		message             string
	)

	switch {
	case errors.As(e, &applicationErr):
		remote = applicationErr.Remote
		desc = fmt.Sprintf("0x%x", int64(applicationErr.ErrorCode))
		message = applicationErr.ErrorMessage
	case errors.As(e, &transportErr):
		remote = transportErr.Remote
		desc = transportErr.ErrorCode.String() + transportErr.ErrorCode.Message()
		message = transportErr.ErrorMessage
	case errors.As(e, &statelessResetErr):
		remote = true
		desc = "stateless_reset"
	case errors.As(e, &vnErr):
		desc = "version_negotiation"
	case errors.As(e, &idleTimeoutErr):
		desc = "idle_timeout"
	case errors.As(e, &handshakeTimeoutErr):
		desc = "handshake_timeout"
	default:
		desc = fmt.Sprintf("unknown error: %v", e)
	}

	side := "local"
	if remote {
		side = "remote"
	}

	connErrors.WithLabelValues(side, desc, message).Inc()
}
