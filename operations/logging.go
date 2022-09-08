package operations

import (
	"github.com/quicsec/quicsec/config"
	"github.com/quicsec/quicsec/utils"
)

var logger utils.Logger

// logInit initialize the logger
func logInit() utils.Logger {
	logger = utils.DefaultLogger

	if config.GetEnableVerbose() {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}

	logFlag, logFile := config.GetLogFileConfig()
	if logFlag {
		f := utils.CreateFileRotate(logFile, 10)
		logger.SetLogOutput(f)
	}

	logger.SetLogTimeFormat(logTimeFormat)

	return logger
}
