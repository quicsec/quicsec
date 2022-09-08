package operations

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/quicsec/quicsec/utils"
)

// qlog initialization - directory where all qlog files will be locate
// create the path if it doesn't exist
// based on the side, add 'server' or 'client' to easy identify the perspective
func qlogInit(qlogDir string) logging.Tracer {
	return qlog.NewTracer(func(pers logging.Perspective, connID []byte) io.WriteCloser {
		// create the directory, if it doesn't exist
		if err := os.MkdirAll(qlogDir, 0777); err != nil {
			logger.Debugf("%s: creating the qlog directory failed: %s", ConstOperationsManager, err)
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
			log.Fatal(err)
		}
		logger.Debugf("%s: qlog file for connection \"%x\" created", ConstOperationsManager, connID)

		return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
	})
}
