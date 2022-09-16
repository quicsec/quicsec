package quicsec

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/quicsec/quicsec/conn"
)

type binds []string

func ListenAndServe(bs []string, handler http.Handler) error {

	if len(bs) == 0 {
		bs = binds{"localhost:8443"}
	}

	var err error
	var wg sync.WaitGroup

	wg.Add(len(bs))
	for _, b := range bs {
		bCap := b
		go func() {
			fmt.Printf("Starting QUIC listener on %s...\n", bs)

			err = conn.ListenAndServe(bCap, handler)

			if err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	return err
}
