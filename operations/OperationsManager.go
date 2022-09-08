package operations

import (
	"io"
	"sync"

	"github.com/lucas-clemente/quic-go/logging"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/utils"
)

const (
	ConstOperationsManager = "Operations Manager"
	ConstIdentityManager   = "Identity Manager"
	ConstConfigManager     = "Configuration Manager"
)

var (
	logTimeFormat = "[Quicsec]"
	onlyOnce      sync.Once
)

func ProbeError(subsystem string, err error) {
	logger.Debugf("%s: error %s", subsystem, err.Error())
}

func GetLogger() utils.Logger {
	return logger
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

	onlyOnce.Do(func() {
		logger = logInit()
		logger.Debugf("%s: initialization", ConstOperationsManager)

		if conf.SharedSecretEnableFlag {
			logger.Debugf("%s: pre shared key dump enabled, dump at:%s", ConstOperationsManager, conf.SharedSecretFilePath)
			keyLog = utils.CreateFileRotate(conf.SharedSecretFilePath, 2)
		} else {
			logger.Debugf("%s: pre shared key dump disabled", ConstOperationsManager)
		}

		if conf.QlogEnableFlag {
			logger.Debugf("%s: qlog enabled (dir:%s)", ConstOperationsManager, conf.QlogDirPath)
			qlogTracer := qlogInit(conf.QlogDirPath)
			tracers = append(tracers, qlogTracer)
		} else {
			logger.Debugf("%s: qlog disabled", ConstOperationsManager)
		}

		if conf.MetricsEnableFlag {
			logger.Debugf("%s: Trace metrics enabled", ConstOperationsManager)
			metricsInit()
			tracers = append(tracers, &MetricsTracer{})
		} else {
			logger.Debugf("%s: Trace metrics disabled", ConstOperationsManager)
		}

		if len(tracers) > 0 {
			tracer = logging.NewMultiplexedTracer(tracers...)
		}
	})

	return logger, keyLog, tracer
}
