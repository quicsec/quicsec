package operations

import (
	"io"
	"sync"

	"github.com/lucas-clemente/quic-go/logging"
	"github.com/quicsec/quicsec/config"
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
	logVerbose        = true // use to set log level
	logTimeFormat     = "[Quicsec]"
	logOutputFileFlag = false
	logOutputFilePath = "./output.log"

	// qlog configs
	qlogEnable  = true
	qlogDirPath = "./qlog"

	// shared secrect for the connection
	sharedSecretEnable   = true
	sharedSecretFilePath = "pre-shared-key.txt"
)

var onlyOnce sync.Once

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
	conf := config.LoadConfig()
	conf.ShowConfig()

	onlyOnce.Do(func() {
		logger = logInit()
		logger.Debugf("%s: initialization", ConstOperationsMan)

		if sharedSecretEnable {
			logger.Debugf("%s: pre shared key dump enabled", ConstOperationsMan)
			keyLog = utils.CreateFileRotate(sharedSecretFilePath, 2)
		} else {
			logger.Debugf("%s: pre shared key dump disabled", ConstOperationsMan)
		}

		if qlogEnable {
			logger.Debugf("%s: qlog enabled (dir:%s)", ConstOperationsMan, qlogDirPath)
			qlogTracer := qlogInit(qlogDirPath)
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
	})

	return logger, keyLog, tracer
}
