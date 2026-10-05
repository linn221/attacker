package fuzz

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
)

type Request struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

type Response struct {
	Id          string
	URL         string
	StatusCode  int
	Latency     uint
	Body500     string
	ContentType string
	BodyHash    string
	Headers     http.Header
	Body        []byte
}

func (r Response) String() string {
	var buf strings.Builder

	w := csv.NewWriter(&buf)

	_ = w.Write([]string{
		r.Id,
		r.URL,
		fmt.Sprint(r.StatusCode),
		r.BodyHash,
		r.ContentType,
		r.Body500,
	})

	w.Flush()

	return strings.TrimSuffix(buf.String(), "\n")
}

func (r *Request) SetDefault() {
	if r.Method == "" {
		r.Method = "GET"
	}
	if r.Headers == nil {
		r.Headers = make(http.Header)
	}
}
