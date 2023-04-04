package log

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/quicsec/quicsec/utils"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var LoggerLgr logr.Logger
var LoggerRequest *zap.Logger

const (
	ConstOperationsManager = "operations_manager"
	ConstIdentityManager   = "identity_manager"
	ConstConfigManager     = "configuration_manager"
	ConstConnManager       = "connection_manager"
	ConstAuthManager       = "authentication_manager"
	ConstQuicSecGeneral    = "quicsec_general"
)

const (
	DebugLevel = 1
)

// logInit initialize the logger
func InitLoggerLogr(debug bool, filePath string) {
	var zapconf zap.Config
	var msgLogFile string

	if debug {
		encConf := zap.NewDevelopmentEncoderConfig()
		encConf.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapconf = zap.NewDevelopmentConfig()
		zapconf.EncoderConfig = encConf

	} else {
		zapconf = zap.NewProductionConfig()
	}

	if filePath != "" {
		// if is not a valid path, send to stdout
		if utils.IsValidPath(filePath) {
			zapconf.OutputPaths = []string{filePath}
			msgLogFile = "valid output log file"
		} else {
			msgLogFile = "invalid output log file, use stdout instead"
		}
	} else {
		msgLogFile = "send output log to stdout"
	}

	z, _ := zapconf.Build()

	LoggerLgr = zapr.NewLogger(z).WithName("Quicsec")
	LoggerLgr.WithName(ConstOperationsManager).Info("logger initialization")
	LoggerLgr.WithName(ConstOperationsManager).Info(msgLogFile, "path", filePath)
}

// logInit initialize the logger
func InitLoggerRequest(debug bool, filePath string) {
	var zapconf zap.Config
	var msgLogFile string

	if debug {
		encConf := zap.NewDevelopmentEncoderConfig()
		encConf.CallerKey = zapcore.OmitKey
		encConf.EncodeLevel = zapcore.CapitalColorLevelEncoder
		zapconf = zap.NewDevelopmentConfig()
		zapconf.EncoderConfig = encConf
	} else {
		zapconf = zap.NewProductionConfig()
		zapconf.EncoderConfig.CallerKey = zapcore.OmitKey
	}

	// if is not a valid path, send to stdout
	if filePath != "" {
		if utils.IsValidPath(filePath) {
			zapconf.OutputPaths = []string{filePath}
			msgLogFile = "valid access file"
		} else {
			msgLogFile = "invalid access file, use stdout instead"
		}
	} else {
		msgLogFile = "send access log to stdout"
	}
	LoggerLgr.WithName(ConstOperationsManager).Info(msgLogFile, "path", filePath)

	z, _ := zapconf.Build()
	LoggerRequest = z
}
