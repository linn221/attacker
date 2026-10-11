package fuzz

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseCurlCommands(t *testing.T) {
	text := `
#!/bin/sh
# comment
echo hello
wget https://example.com/skip
set -e

curl 'https://example.com/search?q=coffee&q=tea' \
  -H 'Accept: text/html' \
  -H 'Cookie: session=abc; theme=dark' \
  --compressed

FOO=1 $ curl -I https://example.com/health
curl https://example.com/a && echo done
curl https://example.com/b; wget https://example.com/nope
curl https://example.com/c | jq .
curl https://example.com/d > /tmp/out
curl https://example.com/e 2>/dev/null
/usr/bin/curl -H 'X: a;b' https://example.com/f
curl --form a=b https://example.com/bad
curl https://example.com/g
`
	browser := "curl 'https://example.com/search?q=coffee&q=tea' \\\n" +
		"  -H 'Accept: text/html' \\\n" +
		"  -H 'Cookie: session=abc; theme=dark' \\\n" +
		"  --compressed"
	wantBrowser, err := ParseCurl(browser)
	if err != nil {
		t.Fatal(err)
	}

	cfgs, errs := ParseCurlCommands(text)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "unsupported curl option --form") {
		t.Fatalf("errors: %v", errs)
	}
	if len(cfgs) != 9 {
		t.Fatalf("got %d configurations, want 9", len(cfgs))
	}
	if !reflect.DeepEqual(cfgs[0], wantBrowser) {
		t.Fatalf("first command\n got %#v\nwant %#v", cfgs[0], wantBrowser)
	}

	var uris []string
	for _, cfg := range cfgs {
		uris = append(uris, deref(cfg.Uri))
	}
	wantURIs := []string{"/search", "/health", "/a", "/b", "/c", "/d", "/e", "/f", "/g"}
	if !reflect.DeepEqual(uris, wantURIs) {
		t.Fatalf("uris %q", uris)
	}
	if cfgs[1].Method == nil || *cfgs[1].Method != "HEAD" {
		t.Fatalf("health method %v", cfgs[1].Method)
	}
	if deref(cfgs[7].Uri) != "/f" || cfgs[7].Headers["X"] != "a;b" {
		t.Fatalf("header command %#v", cfgs[7])
	}
}

func TestParseCurlCommandsQuotes(t *testing.T) {
	cmd := `curl "https://example.com/a" -H "X-Test: a\"b" --data-raw 'it'\''s'`
	text := "echo keep\n" + cmd + "\nls\n"
	want, err := ParseCurl(cmd)
	if err != nil {
		t.Fatal(err)
	}
	cfgs, errs := ParseCurlCommands(text)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(cfgs) != 1 || !reflect.DeepEqual(cfgs[0], want) {
		t.Fatalf("got %#v\nwant %#v\nerrs %v", cfgs, want, errs)
	}
}

func TestParseCurlCommandsSkipsBrokenNonCurl(t *testing.T) {
	text := "echo 'unterminated\ncurl https://example.com/hidden\n"
	cfgs, errs := ParseCurlCommands(text)
	if len(cfgs) != 0 || len(errs) != 0 {
		t.Fatalf("cfgs %#v errs %v", cfgs, errs)
	}
}
