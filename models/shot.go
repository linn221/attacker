package models

import (
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type Shot struct {
	Https       bool
	DomainName  string
	Uri         string
	Method      string
	Headers     map[string]string
	Cookies     map[string][]string
	CookiesText string
	Queries     map[string][]string
	Body        string
}

// ToRequest builds the HTTP request this shot describes.
// An empty method becomes GET. An empty body is left unset.
func (s Shot) ToRequest() (*http.Request, error) {
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

	method := strings.ToUpper(s.Method)
	if method == "" {
		method = http.MethodGet
	}

	var body io.Reader
	if s.Body != "" {
		body = strings.NewReader(s.Body)
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}

	for key, value := range s.Headers {
		req.Header.Set(key, value)
	}
	if cookie := s.cookieHeader(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	return req, nil
}

func (s Shot) cookieHeader() string {
	if s.CookiesText != "" {
		return s.CookiesText
	}
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
