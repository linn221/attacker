package fuzz

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type Shot struct {
	Https      bool
	DomainName string
	Uri        string
	Method     string
	Headers    map[string]string
	Cookies    map[string][]string
	Queries    map[string][]string
	Body       string
}

func (s Shot) ToRequest() Request {
	scheme := "http"
	if s.Https {
		scheme = "https"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   s.DomainName,
		Path:   s.Uri,
	}

	q := u.Query()
	for key, values := range s.Queries {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	u.RawQuery = q.Encode()

	headers := make(http.Header)
	for key, value := range s.Headers {
		headers.Set(key, value)
	}
	if cookie := s.cookieHeader(); cookie != "" {
		headers.Set("Cookie", cookie)
	}

	return Request{
		Method:  strings.ToUpper(s.Method),
		URL:     u.String(),
		Headers: headers,
		Body:    []byte(s.Body),
	}
}

func (s Shot) cookieHeader() string {
	if len(s.Cookies) == 0 {
		return ""
	}
	names := make([]string, 0, len(s.Cookies))
	for name := range s.Cookies {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0)
	for _, name := range names {
		for _, value := range s.Cookies[name] {
			parts = append(parts, name+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

func cloneValues(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, vs := range m {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func cloneHeaders(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s Shot) Clone() Shot {

	t := s
	t.Cookies = cloneValues(s.Cookies)
	t.Headers = cloneHeaders(s.Headers)
	t.Queries = cloneValues(s.Queries)
	return t
}
