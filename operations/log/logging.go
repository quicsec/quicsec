package log

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var LoggerLgr logr.Logger

const (
	ConstOperationsManager = "operations_manager"
	ConstIdentityManager   = "identity_manager"
	ConstConfigManager     = "configuration_manager"
	ConstConnManager       = "connection_manager"
	ConstAuthManager       = "authentication_manager"
)

const (
	DebugLevel = 1
)

// logInit initialize the logger
func InitLoggerLogr(debug bool, filePath string) {
	var zapconf zap.Config

	if debug {
		encConf := zap.NewDevelopmentEncoderConfig()
		encConf.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapconf = zap.NewDevelopmentConfig()
		zapconf.EncoderConfig = encConf

	} else {
		zapconf = zap.NewProductionConfig()
	}

	if filePath != "" {
		zapconf.OutputPaths = []string{filePath}
	}

	z, _ := zapconf.Build()
	LoggerLgr = zapr.NewLogger(z).WithName("Quicsec")
	LoggerLgr.WithName(ConstOperationsManager).Info("logger initialization")
}
