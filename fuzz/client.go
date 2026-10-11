package fuzz

import (
	"context"
	"net/http"
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
