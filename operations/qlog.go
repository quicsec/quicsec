package operations

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quicsec/quicsec/operations/log"
	"github.com/quicsec/quicsec/utils"
)

// qlog initialization - directory where all qlog files will be locate
// create the path if it doesn't exist
// based on the side, add 'server' or 'client' to easy identify the perspective
func qlogInit(qlogDir string) logging.Tracer {
	return qlog.NewTracer(func(pers logging.Perspective, connID []byte) io.WriteCloser {
		// create the directory, if it doesn't exist
		opsLogger := log.LoggerLgr.WithName(log.ConstOperationsManager)

		if err := os.MkdirAll(qlogDir, 0777); err != nil {
			opsLogger.Error(err, "creating the qlog directory failed")
			return nil
		}

		t := time.Now().UTC().Format("2006-01-02T15-04-05.999999999UTC")
		side := "server"
		if pers == logging.PerspectiveClient {
			side = "client"
		}

		filename := fmt.Sprintf("%s/%s_%s_%x.qlog", qlogDir, side, t, connID)

		f, err := os.Create(filename)
		if err != nil {
			opsLogger.Error(err, "creating the qlog file failed")
		}
		opsLogger.V(log.DebugLevel).Info("qlog file created", "ODCID", fmt.Sprintf("%x", connID), "path", filename)

		return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
	})
}
