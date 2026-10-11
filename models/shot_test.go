package models

import (
	"bytes"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestToRequestUsesRawQueryAndStructuredBody(t *testing.T) {
	shot := Shot{
		Https:      false,
		DomainName: "example.com",
		Uri:        "/search",
		Method:     "post",
		Headers:    map[string][]string{"Accept": {"text/html", "application/json"}},
		Queries:    map[string][]string{"q": {"ignored"}},
		QueriesRaw: "a=1&b=2#not-a-fragment",
		BodyJson:   map[string]any{"n": 1},
		BodyForm:   map[string][]string{"a": {"nope"}},
	}
	req, err := shot.ToRequest()
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("method %s", req.Method)
	}
	if req.URL.RawQuery != shot.QueriesRaw {
		t.Fatalf("query %q", req.URL.RawQuery)
	}
	if !reflect.DeepEqual(req.Header.Values("Accept"), []string{"text/html", "application/json"}) {
		t.Fatalf("headers %#v", req.Header)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"n":1}` {
		t.Fatalf("body %s", body)
	}

	shot.BodyRaw = "raw-body"
	req, err = shot.ToRequest()
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "raw-body" {
		t.Fatalf("raw body %s", body)
	}

	form := Shot{BodyForm: map[string][]string{"b": {"2"}, "a": {"1"}}}
	req, err = form.ToRequest()
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "a=1&b=2" {
		t.Fatalf("form body %s", body)
	}
}

func TestWriteRequestSendsInvalidHeadersRaw(t *testing.T) {
	raw := "Not a header \x00\r\nX-Foo: bar\r\n"
	shot := Shot{
		DomainName: "example.com",
		Uri:        "/x",
		Method:     "GET",
		Headers:    map[string][]string{"Accept": {"text/html"}},
		HeadersRaw: raw,
		QueriesRaw: "q=1\r\nInjected: yes",
		BodyRaw:    "payload",
	}
	if !shot.UseRawWire() {
		t.Fatal("expected raw wire")
	}
	var buf bytes.Buffer
	if err := shot.WriteRequest(&buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "GET /x?q=1\r\nInjected: yes HTTP/1.1\r\n") {
		t.Fatalf("request line missing in %q", got)
	}
	if !strings.Contains(got, raw) {
		t.Fatalf("raw headers missing in %q", got)
	}
	if strings.Contains(got, "Accept:") {
		t.Fatalf("map headers were written: %q", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\npayload") {
		t.Fatalf("body framing %q", got)
	}
}
