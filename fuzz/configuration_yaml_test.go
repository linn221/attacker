package fuzz

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigurationYAMLRoundTrip(t *testing.T) {
	text := "echo no\n" +
		"curl 'https://example.com/search?q=coffee&q=tea' -H 'Accept: */*' -H 'Cookie: session=abc; theme=dark'\n" +
		"curl -X POST https://api.example.com:8443/v1/users -H 'Content-Type: application/json' --data-raw '{\"name\":\"ada\"}'\n" +
		"curl http://example.com/health\n"
	cfgs, errs := ParseCurlCommands(text)
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	data, err := MarshalConfigurations(cfgs)
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	for _, part := range []string{
		"domainName: example.com",
		"uri: /search",
		"method: GET",
		"Accept: '*/*'",
		"session: abc",
		"theme: dark",
		"q:",
		"- coffee",
		"- tea",
		"domainName: api.example.com:8443",
		"uri: /v1/users",
		"method: POST",
		`body: '{"name":"ada"}'`,
		"bodyJson:",
		"name: ada",
		"https: false",
	} {
		if !strings.Contains(src, part) {
			t.Fatalf("missing %q in\n%s", part, src)
		}
	}
	if strings.Index(src, "uri: /search") > strings.Index(src, "uri: /v1/users") {
		t.Fatalf("configurations are out of order:\n%s", src)
	}

	got := UnmarshalConfigurations(data)
	if !reflect.DeepEqual(got, cfgs) {
		t.Fatalf("round trip\n got %#v\nwant %#v", got, cfgs)
	}

	empty, err := MarshalConfigurations(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != "[]\n" {
		t.Fatalf("empty yaml %q", empty)
	}
	loaded := UnmarshalConfigurations(nil)
	if len(loaded) != 0 {
		t.Fatalf("empty decode %#v", loaded)
	}
}

func TestLoadConfigurationFile(t *testing.T) {
	https := true
	domain := "example.com"
	uri := "/search"
	method := "GET"
	body := "name=ada"
	cfgs := []Configuration{{
		Https:      &https,
		DomainName: &domain,
		Uri:        &uri,
		Method:     &method,
		Headers:    map[string]string{"Accept": "text/html"},
		Cookies:    map[string]string{"session": "abc"},
		Queries:    map[string][]string{"q": {"coffee", "tea"}},
		Body:       &body,
	}}

	dir := t.TempDir()
	path := filepath.Join(dir, "requests.yml")
	if err := SaveConfigurations(path, cfgs); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %o", info.Mode().Perm())
	}

	got := LoadConfigurations(path)
	if !reflect.DeepEqual(got, cfgs) {
		t.Fatalf("load\n got %#v\nwant %#v", got, cfgs)
	}

	fz := NewFuzzer(&Shot{})
	if err := fz.LoadConfigurationFile(path); err != nil {
		t.Fatal(err)
	}
	shots := fz.Fuzz()
	if len(shots) != 1 {
		t.Fatalf("shots %d", len(shots))
	}
	shot := shots[0]
	if !shot.Https || shot.DomainName != domain || shot.Uri != uri || shot.Method != method || shot.BodyRaw != body {
		t.Fatalf("shot %#v", shot)
	}
	if !reflect.DeepEqual(shot.Headers["Accept"], []string{"text/html"}) || len(shot.Cookies["session"]) != 1 || shot.Cookies["session"][0] != "abc" {
		t.Fatalf("shot maps %#v %#v", shot.Headers, shot.Cookies)
	}
	if !reflect.DeepEqual(shot.Queries["q"], []string{"coffee", "tea"}) {
		t.Fatalf("queries %#v", shot.Queries)
	}
}

func TestUnmarshalConfigurationsRejectsUnknownField(t *testing.T) {
	defer func() {
		recovered, _ := recover().(string)
		if !strings.Contains(recovered, "nope") {
			t.Fatalf("panic %q", recovered)
		}
	}()
	UnmarshalConfigurations([]byte("- https: true\n  nope: 1\n"))
}
