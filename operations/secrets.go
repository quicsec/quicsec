package operations

import (
	"io"
	"log"
	"os"
)

const (
	MiB     = 1048576 // mebibyte
	maxSize = 2 * MiB // max size of pre shared secrets
)

// shared secrets initialization - path to store the shared secrets dumped
// always append, unless the file has 2MB size (crates a new one)
func ssecretsInit(ssecretsFile string) io.Writer {
	var size int64

	fs, err := os.Stat(ssecretsFile)
	if err == nil {
		size = fs.Size()
	}

	if size > maxSize {
		os.Remove(ssecretsFile)
	}

	f, err := os.OpenFile(ssecretsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	logger.Debugf("%s: recording pre shared key (file:%s)", ConstOperationsMan, ssecretsFile)

	return f
}
