package fuzz

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/linn221/attacker/models"
)

type Client struct {
	HTTPClient *http.Client
	Context    context.Context
}

// Do sends req with the client's HTTP client.
// A context on the client replaces the request context. An empty method becomes GET.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if c.Context != nil {
		req = req.WithContext(c.Context)
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return httpClient.Do(req)
}

// Send delivers shot and returns the response plus the request that describes it.
// HeadersRaw, and a QueriesRaw value net/http would reject, are written as raw
// HTTP/1.1 bytes so invalid header text is still sent unchanged.
func (c *Client) Send(shot models.Shot) (*http.Response, *http.Request, error) {
	if shot.UseRawWire() {
		return c.sendRaw(shot)
	}
	req, err := shot.ToRequest()
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, req, err
	}
	return resp, req, nil
}

func (c *Client) sendRaw(shot models.Shot) (*http.Response, *http.Request, error) {
	method := strings.ToUpper(shot.Method)
	if method == "" {
		method = http.MethodGet
	}
	req := &http.Request{
		Method:     method,
		URL:        shot.URL(),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	ctx := c.Context
	if ctx == nil {
		ctx = context.Background()
	}
	host := shot.DomainName
	if host == "" {
		host = req.URL.Host
	}
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		port := "80"
		if shot.Https {
			port = "443"
		}
		addr = net.JoinHostPort(host, port)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, req, err
	}
	if shot.Https {
		serverName := host
		if name, _, err := net.SplitHostPort(host); err == nil {
			serverName = name
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, req, err
		}
		conn = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	stop := func() { close(done) }

	if err := shot.WriteRequest(conn); err != nil {
		stop()
		conn.Close()
		return nil, req, err
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		stop()
		conn.Close()
		return nil, req, err
	}
	resp.Body = &bodyCloser{ReadCloser: resp.Body, conn: conn, stop: stop}
	return resp, req, nil
}

type bodyCloser struct {
	io.ReadCloser
	conn net.Conn
	stop func()
	once sync.Once
}

func (b *bodyCloser) Close() error {
	b.once.Do(b.stop)
	err1 := b.ReadCloser.Close()
	err2 := b.conn.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
