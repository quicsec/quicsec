package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/quicsec/quicsec"
)

type cliStruct struct {
	client *quicsec.Client
}

var (
	headers = map[string]string{
		"client-app": "quicsec-client",
		"user-agent": "golang-quicsec-client/3",
	}

	interestingHeaders = []string{
		"Server",
		"Date",
	}
)

func getHeader(headers map[string][]string, header string) string {
	val, ok := headers[header]
	if !ok {
		val = []string{"n/a"}
	}
	return strings.Join(val, ", ")
}

func main() {
	url := flag.String("url", "", "url to fetch")
	mult := flag.Int("mult", 1, "how many requests in a loop")

	flag.Parse()

	req, err := http.NewRequest("GET", *url, nil)

	if err != nil {
		fmt.Printf("Error requesting %s: %s\n", *url, err)
	}

	for headerKey, headerValue := range headers {
		req.Header.Add(headerKey, headerValue)
	}

	for i := 0; i < *mult; i++ {
		// approach 1
		// resp, err := quicsec.Do(req)

		// approach 2
		s := &cliStruct{client: &quicsec.Client{}}
		resp, err := s.client.Do(req)

		if err != nil {
			fmt.Printf("Error fetching %s: %s\n", *url, err)
		} else {
			defer resp.Body.Close()

			fmt.Println("#################################################")
			fmt.Printf("\t\tRESULTS\n")
			fmt.Println("#################################################")

			fmt.Printf("Request-url: \n\t\t%s\n", *url)

			fmt.Println("Request-headers:")

			for k, v := range req.Header {
				fmt.Printf("\t\t%s : %s\n", k, v)
			}

			fmt.Println("Response-headers:")

			for k, v := range resp.Header {
				fmt.Printf("\t\t%s : %s\n", k, v)
			}
			fmt.Printf("Status: \n\t\t%s\n", resp.Status)

			fmt.Println("Response Body:")

			body := &bytes.Buffer{}

			_, err = io.Copy(body, resp.Body)

			if err != nil {
				fmt.Println(err)
			}

			fmt.Printf("\t\t%s", body.Bytes())
		}
	}
}
