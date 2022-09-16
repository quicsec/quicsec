package operations

import (
	"io"

	"github.com/lucas-clemente/quic-go/logging"
	"github.com/quicsec/quicsec/utils"
)

const (
	ConstOperationsMan = "Operations Manager"
	ConstIdentityMan   = "Identity Manager"
)

// configuration - should be confiruable by the Config Manager */
var (
	// Metrics and Prometheus configs
	metricsEnable          = true
	prometheusServerEnable = true // data avaiable by http server

	// Log configs
	logVerbose    = true // use to set log level
	logTimeFormat = "[Quicsec]"

	// qlog configs
	qlogEnable   = true
	qlogFilePath = "./qlog"

	// shared secrect for the connection
	sharedSecretEnable = true
	sharedSecretFile   = "pre-shared-key.txt"
)

var logger utils.Logger

// logInit initialize the logger
func logInit() utils.Logger {
	logger = utils.DefaultLogger

	if logVerbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat(logTimeFormat)

	return logger
}

func ProbeError(subsystem string, err error) {
	logger.Debugf("%s: error %s", subsystem, err.Error())
}

// OperationsInit initialize the Operations Manager
// The following tasks are:
// 1. Starts the logger
// 2. Creates the shared secret file to dump the traffic secrets
// 3. Creates the qlog
// 4. Start tracing the metrics
func OperationsInit() (utils.Logger, io.Writer, logging.Tracer) {
	var tracers []logging.Tracer
	var tracer logging.Tracer
	var keyLog io.Writer

	logger = logInit()
	logger.Debugf("%s: initialization", ConstOperationsMan)

	if sharedSecretEnable {
		logger.Debugf("%s: pre shared key dump enabled", ConstOperationsMan)
		keyLog = ssecretsInit(sharedSecretFile)
	} else {
		logger.Debugf("%s: pre shared key dump disabled", ConstOperationsMan)
	}

	if qlogEnable {
		logger.Debugf("%s: qlog enabled (dir:%s)", ConstOperationsMan, qlogFilePath)
		qlogTracer := qlogInit(qlogFilePath)
		tracers = append(tracers, qlogTracer)
	} else {
		logger.Debugf("%s: qlog disabled", ConstOperationsMan)
	}

	if metricsEnable {
		logger.Debugf("%s: Trace metrics enabled", ConstOperationsMan)
		metricsInit()
		tracers = append(tracers, &MetricsTracer{})
	} else {
		logger.Debugf("%s: Trace metrics disabled", ConstOperationsMan)
	}

	if len(tracers) > 0 {
		tracer = logging.NewMultiplexedTracer(tracers...)
	}

	return logger, keyLog, tracer
}
