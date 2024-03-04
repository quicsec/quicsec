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
		"header3":    "value3",
		"header4":    "value4",
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
	method := flag.String("method", "GET", "HTTP method (GET or POST)")
	mult := flag.Int("mult", 1, "how many requests in a loop")
	flag.Parse()

	// Add a large body for POST requests
	largeBodyStr := strings.Repeat(`{"key": "value", "repeat": "This is a large body for POST requests. "}`, 2) // Repeat the string to make it large
	var body io.Reader

	flag.Parse()

	if *method == "POST" {
		body = bytes.NewBufferString(largeBodyStr)
	} else {
		body = nil // GET request doesn't typically have a body
	}

	req, err := http.NewRequest(*method, *url, body)

	if err != nil {
		fmt.Printf("Error creating request: %s\n", err)
		return
	}

	// Set headers
	for headerKey, headerValue := range headers {
		req.Header.Add(headerKey, headerValue)
	}
	if *method == "POST" {
		req.Header.Set("Content-Type", "application/json") // Assuming JSON body for POST
	}

	for i := 0; i < *mult; i++ {
		// Using approach 2 as an example
		s := &cliStruct{client: &quicsec.Client{}}
		resp, err := s.client.Do(req)

		if err != nil {
			fmt.Printf("Error fetching %s: %s\n", *url, err)
			continue // Skip further processing on error
		}
		defer resp.Body.Close()

		// Output results as before...
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
