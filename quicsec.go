package quicsec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quicsec/quicsec/conn"
	"github.com/quicsec/quicsec/operations/log"
)

type Client struct {
	Client *http.Client
}

type Server struct {
	Server *http.Server
}

type HttpClientInterface interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
	Head(url string) (*http.Response, error)
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
	CloseIdleConnections()
}

type HttpServerPrototype interface {
	ListenAndServe() error
	ListenAndServeTLS(certFile, keyFile string) error
	SetKeepAlivesEnabled(v bool)
	Shutdown(ctx context.Context) error
	Close() error
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return Do(req)
}

func (c *Client) Get(url string) (*http.Response, error) {
	return c.Client.Get(url)
}

func (c *Client) Head(url string) (*http.Response, error) {
	return c.Client.Head(url)
}

func (c *Client) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	return c.Client.Post(url, contentType, body)
}

func (c *Client) PostForm(url string, data url.Values) (*http.Response, error) {
	return c.Client.PostForm(url, data)
}

func (c *Client) CloseIdleConnections() {
	c.Client.CloseIdleConnections()
}

func (s *Server) ListenAndServe(addr string, handler http.Handler) error {
	return ListenAndServe(addr, handler)
}

func (s *Server) ListenAndServeTLS(certFile, keyFile string) error {
	return s.Server.ListenAndServeTLS(certFile, keyFile)
}

func (s *Server) SetKeepAlivesEnabled(v bool) {
	s.Server.SetKeepAlivesEnabled(v)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}

func (s *Server) Close() error {
	return s.Server.Close()
}

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

	quicSecLogger.V(log.DebugLevel).Info("Request total time", "total_req_time", elapsed)

	return resp, err
}
