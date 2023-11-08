package operations

import (
	"io"
	"sync"

	"github.com/quic-go/quic-go/logging"
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/identity"
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

	//[TODO] configmanager is originaly being initialized here. Maybe we should move it to server/client init.
	config.InitConfigManager()

	onlyOnce.Do(func() {

		opsLogger := log.LoggerLgr.WithName(log.ConstOperationsManager)

		opsLogger.Info("module initialization")

		if config.GetQuicDebugSecretFilePathEnabled() {
			opsLogger.V(log.DebugLevel).Info("pre shared key dump enabled", "path", config.GetQuicDebugSecretFilePath())

			keyLog = utils.CreateFileRotate(config.GetQuicDebugSecretFilePath(), 2)
		} else {
			opsLogger.V(log.DebugLevel).Info("pre shared key dump disabled")
		}

		if config.GetQuicDebugQlogEnabled() {
			opsLogger.V(log.DebugLevel).Info("qlog enabled", "path", config.GetQuicDebugQlogDirPath())

			qlogTracer := qlogInit(config.GetQuicDebugQlogDirPath())
			tracers = append(tracers, qlogTracer)
		} else {
			opsLogger.V(log.DebugLevel).Info("qlog disabled")
		}

		if config.GetMetricsEnabled() {
			opsLogger.V(log.DebugLevel).Info("trace metrics enabled")
			metricsInit()
			tracers = append(tracers, &MetricsTracer{})
		} else {
			opsLogger.V(log.DebugLevel).Info("trace metrics disabled")
		}

		if len(tracers) > 0 {
			tracer = logging.NewMultiplexedTracer(tracers...)
		}

		currentId, err := identity.GetCurrentIdentity()
		if err == nil {
			config.SetIdentity(currentId)
		}
	})

	return keyLog, tracer
}
