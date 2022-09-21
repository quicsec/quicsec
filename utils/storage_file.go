package utils

import (
	"io"
	"log"
	"os"
)

const (
	MiB = 1 << 20 // 1 MB
)

// createFileRotate - create(append) in the file point by 'filePath'
// If the size of the file reach the 'maxSize', delete and create a
// new one
func CreateFileRotate(filePath string, maxSize int64) io.Writer {
	var size int64

	fs, err := os.Stat(filePath)
	if err == nil {
		size = fs.Size()
	}

	if size > (maxSize * MiB) {
		os.Remove(filePath)
	}

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	return f
}
