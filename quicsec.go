package quicsec

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"

	"github.com/quicsec/quicsec/utils"
)

type binds []string

func ListenAndServe(bs []string, handler http.Handler) error {
	certFile, keyFile := getIndentityPaths()

	if len(bs) == 0 {
		bs = binds{"localhost:8443"}
	}

	var err error
	var wg sync.WaitGroup

	enableQlog := true

	quicConf := &quic.Config{}
	if enableQlog {
		quicConf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("server_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			fmt.Printf("Starting QUIC listener on %s...\n", bs)
			// [TODO]: using ListenAndServer from quic-go/http3. Internally it create a fresh new tls.config.
			// 		   we probably will need to take control of tls.config. To do that we need to owerwrite the
			//  	   tls config.
			err = http3.ListenAndServe(bCap, certFile, keyFile, handler)

			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	return err
}
