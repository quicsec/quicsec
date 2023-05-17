package quicsec

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/quicsec/quicsec/conn"
	"github.com/quicsec/quicsec/operations/log"
)

type binds []string

func ListenAndServe(addr string, handler http.Handler) error {

	if len(addr) == 0 {
		addr = "localhost:8443"
	}

	var err error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		fmt.Printf("Starting QUIC listener on %s...\n", addr)

		err = conn.ListenAndServe(addr, handler)

		if err != nil {
			fmt.Println(err)
		}
		wg.Done()
	}()
	wg.Wait()

	return err
}

func Do(req *http.Request) (*http.Response, error) {
	start := time.Now()

	resp, err := conn.Do(req)

	quicSecLogger := log.LoggerLgr.WithName(log.ConstQuicSecGeneral)
	elapsed := time.Since(start).Seconds()

	quicSecLogger.Info("Request total time", "total_req_time", elapsed)

	return resp, err
}
