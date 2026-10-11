package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// requests that are pending to be sent by the server via job
// will be stored as json files on disk
// can be unusal, intentionally corrupted for fuzzing use case
type Shot struct {
	Https      bool
	DomainName string
	Uri        string
	Method     string
	Headers    map[string][]string
	HeadersRaw string
	Cookies    map[string][]string
	CookiesRaw string
	Queries    map[string][]string
	QueriesRaw string
	BodyRaw    string
	BodyJson   any
	BodyForm   map[string][]string
}

// URL is the request URL.
// QueriesRaw, when set, is copied into the query without encoding.
// Otherwise the query is built from Queries.
func (s Shot) URL() *url.URL {
	scheme := "http"
	if s.Https {
		scheme = "https"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   s.DomainName,
		Path:   s.Uri,
	}
	if s.QueriesRaw != "" {
		u.RawQuery = s.QueriesRaw
		return u
	}
	if len(s.Queries) == 0 {
		return u
	}
	q := url.Values{}
	for key, values := range s.Queries {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u
}

// UseRawWire reports whether the request must be written as raw HTTP/1.1 bytes.
// HeadersRaw is sent unchanged, which net/http cannot do: it drops invalid header
// names and rewrites values. A query that contains a control character is also
// rejected by Request.Write, so that case is written the same way.
func (s Shot) UseRawWire() bool {
	if s.HeadersRaw != "" {
		return true
	}
	for i := 0; i < len(s.QueriesRaw); i++ {
		if s.QueriesRaw[i] < ' ' || s.QueriesRaw[i] == 0x7f {
			return true
		}
	}
	return false
}

// ToRequest builds the HTTP request this shot describes.
// An empty method becomes GET. HeadersRaw is not applied here; callers use
// WriteRequest when UseRawWire is set. QueriesRaw replaces Queries.
// BodyRaw is sent as-is. Otherwise BodyJson is marshaled, then BodyForm is encoded.
func (s Shot) ToRequest() (*http.Request, error) {
	method := requestMethod(s.Method)
	payload, err := s.bodyBytes()
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if len(payload) > 0 {
		body = bytes.NewReader(payload)
	}

	u := s.URL()
	rawQuery := u.RawQuery
	u.RawQuery = ""
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = rawQuery

	for key, values := range s.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if cookie := s.cookieHeader(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	return req, nil
}

// WriteRequest writes an HTTP/1.1 request to w.
// When HeadersRaw is set, those bytes are copied after the request line and are
// not parsed, canonicalized, or dropped. A missing blank line is added after
// them so a body is not glued onto the header block. The header text itself is
// left unchanged, including text that is not a valid header.
func (s Shot) WriteRequest(w io.Writer) error {
	method := requestMethod(s.Method)
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", method, s.URL().RequestURI()); err != nil {
		return err
	}
	if s.HeadersRaw != "" {
		if _, err := io.WriteString(w, s.HeadersRaw); err != nil {
			return err
		}
		if !strings.HasSuffix(s.HeadersRaw, "\n") {
			if _, err := io.WriteString(w, "\r\n"); err != nil {
				return err
			}
		}
		if !headerBlockClosed(s.HeadersRaw) {
			if _, err := io.WriteString(w, "\r\n"); err != nil {
				return err
			}
		}
	} else if err := s.writeConstructedHeaders(w); err != nil {
		return err
	}
	payload, err := s.bodyBytes()
	if err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// BodyText is the request body that will be sent.
// BodyRaw wins when it is not empty. Otherwise BodyJson is marshaled, then BodyForm.
func (s Shot) BodyText() (string, error) {
	payload, err := s.bodyBytes()
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func (s Shot) bodyBytes() ([]byte, error) {
	if s.BodyRaw != "" {
		return []byte(s.BodyRaw), nil
	}
	if s.BodyJson != nil {
		return json.Marshal(s.BodyJson)
	}
	if len(s.BodyForm) == 0 {
		return nil, nil
	}
	v := make(url.Values, len(s.BodyForm))
	for key, values := range s.BodyForm {
		for _, value := range values {
			v.Add(key, value)
		}
	}
	return []byte(v.Encode()), nil
}

func (s Shot) writeConstructedHeaders(w io.Writer) error {
	names := make([]string, 0, len(s.Headers))
	for name := range s.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	hasHost := false
	for _, name := range names {
		if strings.EqualFold(name, "Host") {
			hasHost = true
		}
		for _, value := range s.Headers[name] {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}
	if cookie := s.cookieHeader(); cookie != "" {
		if _, err := fmt.Fprintf(w, "Cookie: %s\r\n", cookie); err != nil {
			return err
		}
	}
	if !hasHost && s.DomainName != "" {
		if _, err := fmt.Fprintf(w, "Host: %s\r\n", s.DomainName); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func headerBlockClosed(raw string) bool {
	return strings.HasSuffix(raw, "\r\n\r\n") || strings.HasSuffix(raw, "\n\n")
}

func requestMethod(method string) string {
	method = strings.ToUpper(method)
	if method == "" {
		return http.MethodGet
	}
	return method
}

func (s Shot) cookieHeader() string {
	if s.CookiesRaw != "" {
		return s.CookiesRaw
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

func cloneAny(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

func (s Shot) Clone() Shot {
	t := s
	t.Cookies = cloneValues(s.Cookies)
	t.Headers = cloneValues(s.Headers)
	t.Queries = cloneValues(s.Queries)
	t.BodyForm = cloneValues(s.BodyForm)
	t.BodyJson = cloneAny(s.BodyJson)
	return t
}
