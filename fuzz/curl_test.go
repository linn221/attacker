package fuzz

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCurl(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    Configuration
		wantErr string
	}{
		{
			name: "browser get",
			command: "curl 'https://example.com/search?q=coffee&q=tea' \\\n" +
				"  -H 'Accept: text/html' \\\n" +
				"  -H 'Cookie: session=abc; theme=dark' \\\n" +
				"  --compressed",
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/search"),
				Method:     strPtr("GET"),
				Headers:    map[string]string{"Accept": "text/html"},
				Cookies: map[string]string{
					"session": "abc",
					"theme":   "dark",
				},
				Queries: map[string][]string{"q": {"coffee", "tea"}},
			},
		},
		{
			name:    "post json",
			command: `curl -X POST https://api.example.com:8443/v1/users -H 'Content-Type: application/json' --data-raw '{"name":"ada"}'`,
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("api.example.com:8443"),
				Uri:        strPtr("/v1/users"),
				Method:     strPtr("POST"),
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       strPtr(`{"name":"ada"}`),
				BodyJson:   map[string]any{"name": "ada"},
			},
		},
		{
			name:    "form data defaults to post",
			command: `curl https://example.com/login -d 'user=ada' -d 'password=secret'`,
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/login"),
				Method:     strPtr("POST"),
				Headers:    map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:       strPtr("user=ada&password=secret"),
				BodyForm: map[string][]string{
					"user":     {"ada"},
					"password": {"secret"},
				},
			},
		},
		{
			name:    "get flag moves data into the query",
			command: `curl -G 'http://example.com/s?x=1' --data 'q=2' --data-urlencode 'name=a b'`,
			want: Configuration{
				Https:      boolPtr(false),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/s"),
				Method:     strPtr("GET"),
				Queries: map[string][]string{
					"x":    {"1"},
					"q":    {"2"},
					"name": {"a b"},
				},
			},
		},
		{
			name:    "json flag",
			command: `curl --json '{"a":1}' https://example.com/`,
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/"),
				Method:     strPtr("POST"),
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
				Body:     strPtr(`{"a":1}`),
				BodyJson: map[string]any{"a": 1},
			},
		},
		{
			name:    "basic auth overrides url user",
			command: `curl https://other:secret@example.com/admin -u user:pass -A agent -e https://ref.example`,
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/admin"),
				Method:     strPtr("GET"),
				Headers: map[string]string{
					"Authorization": basicAuth("user:pass"),
					"User-Agent":    "agent",
					"Referer":       "https://ref.example",
				},
			},
		},
		{
			name:    "head and short flags",
			command: `curl -sSkI https://example.com/health`,
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/health"),
				Method:     strPtr("HEAD"),
			},
		},
		{
			name:    "quoted concatenation and escapes",
			command: `curl "https://example.com/a" -H "X-Test: a\"b" --data-raw 'it'\''s'`,
			want: Configuration{
				Https:      boolPtr(true),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/a"),
				Method:     strPtr("POST"),
				Headers: map[string]string{
					"X-Test":       `a"b`,
					"Content-Type": "application/x-www-form-urlencoded",
				},
				Body:     strPtr("it's"),
				BodyForm: map[string][]string{"it's": {""}},
			},
		},
		{
			name:    "scheme-less url",
			command: `curl example.com/search`,
			want: Configuration{
				Https:      boolPtr(false),
				DomainName: strPtr("example.com"),
				Uri:        strPtr("/search"),
				Method:     strPtr("GET"),
			},
		},
		{
			name:    "missing url",
			command: `curl -H 'Accept: text/html'`,
			wantErr: "missing a url",
		},
		{
			name:    "unsupported form",
			command: `curl --form a=b https://example.com`,
			wantErr: "unsupported curl option --form",
		},
		{
			name:    "unterminated quote",
			command: `curl 'https://example.com`,
			wantErr: "unterminated quote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCurl(tt.command)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseCurl()\n got %#v\nwant %#v", got, tt.want)
			}
		})
	}
}

func TestParseCurlDataFile(t *testing.T) {
	dir := t.TempDir()
	form := filepath.Join(dir, "form.txt")
	if err := os.WriteFile(form, []byte("a=1\nb=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "raw.txt")
	if err := os.WriteFile(raw, []byte("a=1\nb=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ParseCurl("curl https://example.com/upload --data @" + form)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body == nil || *got.Body != "a=1b=2" {
		t.Fatalf("data file body %q", deref(got.Body))
	}
	if !reflect.DeepEqual(got.BodyForm, map[string][]string{"a": {"1b=2"}}) {
		t.Fatalf("data file form %#v", got.BodyForm)
	}

	got, err = ParseCurl("curl https://example.com/upload --data-binary @" + raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body == nil || *got.Body != "a=1\nb=2\n" {
		t.Fatalf("binary file body %q", deref(got.Body))
	}

	got, err = ParseCurl("curl https://example.com/upload --data-raw @" + form)
	if err != nil {
		t.Fatal(err)
	}
	if got.Body == nil || *got.Body != "@"+form {
		t.Fatalf("raw body %q", deref(got.Body))
	}
}

func TestParseCurlDropsBrowserNoiseHeaders(t *testing.T) {
	command := `curl 'https://example.com/a' ` +
		`-H 'Accept: application/json' ` +
		`-H 'Accept-Encoding: gzip, deflate, br' ` +
		`-H 'Accept-Language: en' ` +
		`-H 'Alt-Used: example.com' ` +
		`-H 'Authorization: Bearer t' ` +
		`-H 'Cache-Control: no-cache' ` +
		`-H 'Connection: keep-alive' ` +
		`-H 'If-None-Match: "abc"' ` +
		`-H 'Pragma: no-cache' ` +
		`-H 'Priority: u=4' ` +
		`-H 'Sec-Fetch-Dest: empty' ` +
		`-H 'Sec-Fetch-Mode: cors' ` +
		`-H 'Sec-Fetch-Site: same-origin' ` +
		`-H 'TE: trailers' ` +
		`-H 'Upgrade-Insecure-Requests: 1' ` +
		`-H 'User-Agent: Mozilla/5.0' ` +
		`-H 'X-Caller: app' ` +
		`-H 'access-control-allow-origin: *'`
	got, err := ParseCurl(command)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Accept":          "application/json",
		"Accept-Language": "en",
		"Authorization":   "Bearer t",
		"User-Agent":      "Mozilla/5.0",
		"X-Caller":        "app",
	}
	if !reflect.DeepEqual(got.Headers, want) {
		t.Fatalf("headers %#v", got.Headers)
	}
}

func TestStructuredBody(t *testing.T) {
	jsonCmd := `curl -X POST https://example.com/j -H 'Content-Type: application/json; charset=utf-8' --data-raw '{"n":1,"f":1.5,"ok":false,"tags":["a"],"child":{"x":"y"}}'`
	cfg, err := ParseCurl(jsonCmd)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Body == nil || *cfg.Body != `{"n":1,"f":1.5,"ok":false,"tags":["a"],"child":{"x":"y"}}` {
		t.Fatalf("raw body %q", deref(cfg.Body))
	}
	wantJSON := map[string]any{
		"n":     1,
		"f":     1.5,
		"ok":    false,
		"tags":  []any{"a"},
		"child": map[string]any{"x": "y"},
	}
	if !reflect.DeepEqual(cfg.BodyJson, wantJSON) {
		t.Fatalf("bodyJson %#v", cfg.BodyJson)
	}
	if cfg.BodyForm != nil {
		t.Fatalf("json body also set form %#v", cfg.BodyForm)
	}
	data, err := MarshalConfigurations([]Configuration{cfg})
	if err != nil {
		t.Fatal(err)
	}
	got := UnmarshalConfigurations(data)
	if !reflect.DeepEqual(got, []Configuration{cfg}) {
		t.Fatalf("json round trip\n got %#v\nwant %#v", got, []Configuration{cfg})
	}

	form, err := ParseCurl(`curl https://example.com/login --data-urlencode 'name=a b' -d 'id=1' -d 'id=2'`)
	if err != nil {
		t.Fatal(err)
	}
	if form.Body == nil || *form.Body != "name=a%20b&id=1&id=2" {
		t.Fatalf("form body %q", deref(form.Body))
	}
	wantForm := map[string][]string{"name": {"a b"}, "id": {"1", "2"}}
	if !reflect.DeepEqual(form.BodyForm, wantForm) {
		t.Fatalf("bodyForm %#v", form.BodyForm)
	}
	if form.BodyJson != nil {
		t.Fatalf("form body also set json %#v", form.BodyJson)
	}

	bare, err := ParseCurl(`curl https://example.com/j -d '{"z":true}'`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bare.BodyJson, map[string]any{"z": true}) {
		t.Fatalf("json text with form content type %#v header %#v", bare.BodyJson, bare.Headers)
	}
	if bare.BodyForm != nil {
		t.Fatalf("json text also set form %#v", bare.BodyForm)
	}

	broken, err := ParseCurl(`curl https://example.com/j -H 'Content-Type: application/json' --data-raw 'not-json'`)
	if err != nil {
		t.Fatal(err)
	}
	if broken.BodyJson != nil || broken.BodyForm != nil {
		t.Fatalf("invalid json body %#v %#v", broken.BodyJson, broken.BodyForm)
	}
}

func boolPtr(v bool) *bool { return &v }

func strPtr(v string) *string { return &v }

func deref(v *string) string {
	if v == nil {
		return "<nil>"
	}
	return *v
}
