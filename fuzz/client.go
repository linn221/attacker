package fuzz

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

type Client struct {
	HTTPClient *http.Client
}

func (c *Client) Do(req Request) (Response, error) {
	req.SetDefault()

	httpReq, err := http.NewRequest(
		req.Method,
		req.URL,
		bytes.NewReader(req.Body),
	)
	if err != nil {
		return Response{}, err
	}

	for name, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(name, value)
		}
	}

	then := time.Now()
	httpResp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return Response{}, err
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return Response{}, err
	}
	latency := time.Since(then)
	ct := httpResp.Header.Get("Content-Type")
	n := min(len(body), 500)
	sum := string(body)[:n]

	id, err := randomString(16)
	if err != nil {
		return Response{}, err
	}
	return Response{
		Id:          id,
		URL:         req.URL,
		Latency:     uint(latency),
		ContentType: ct,
		StatusCode:  httpResp.StatusCode,
		Headers:     httpResp.Header,
		Body:        body,
		Body500:     sum,
		BodyHash:    md5Hash(string(body)),
	}, nil
}
