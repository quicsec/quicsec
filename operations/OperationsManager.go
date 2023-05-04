package operations

import (
	"io"
	"sync"

	"github.com/quic-go/quic-go/logging"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/utils"
)

var (
	onlyOnce sync.Once
)

// OperationsInit initialize the Operations Manager
// The following tasks are:
// 1. Starts the logger
// 2. Creates the shared secret file to dump the traffic secrets
// 3. Creates the qlog
// 4. Start tracing the metrics
func OperationsInit() (io.Writer, logging.Tracer) {
	var tracers []logging.Tracer
	var tracer logging.Tracer
	var keyLog io.Writer
	conf := config.LoadConfig()

	onlyOnce.Do(func() {

		opsLogger := log.LoggerLgr.WithName(log.ConstOperationsManager)

		opsLogger.Info("module initialization")

		if conf.Quic.Debug.SecretFilePathEnableFlag {
			opsLogger.V(log.DebugLevel).Info("pre shared key dump enabled", "path", conf.Quic.Debug.SecretFilePath)

			keyLog = utils.CreateFileRotate(conf.Quic.Debug.SecretFilePath, 2)
		} else {
			opsLogger.V(log.DebugLevel).Info("pre shared key dump disabled")
		}

		if conf.Quic.Debug.QlogEnableFlag {
			opsLogger.V(log.DebugLevel).Info("qlog enabled", "path", conf.Quic.Debug.QlogDirPath)

			qlogTracer := qlogInit(conf.Quic.Debug.QlogDirPath)
			tracers = append(tracers, qlogTracer)
		} else {
			opsLogger.V(log.DebugLevel).Info("qlog disabled")
		}

		if conf.Metrics.Enable {
			opsLogger.V(log.DebugLevel).Info("trace metrics enabled")
			metricsInit()
			tracers = append(tracers, &MetricsTracer{})
		} else {
			opsLogger.V(log.DebugLevel).Info("trace metrics disabled")
		}

		if len(tracers) > 0 {
			tracer = logging.NewMultiplexedTracer(tracers...)
		}
	})

	return keyLog, tracer
}
