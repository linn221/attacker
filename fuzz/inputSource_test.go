package fuzz

import (
	"reflect"
	"testing"
)

func TestFuzzInputSourceQuery(t *testing.T) {
	base := Shot{
		Https:      true,
		DomainName: "example.com",
		Uri:        "/search",
		Method:     "GET",
		Headers:    map[string][]string{"Accept": {"text/html"}},
		Queries:    map[string][]string{"q": {"coffee", "tea"}, "page": {"1"}},
	}

	shots := FuzzInputSource(base)
	if len(shots) != 3 {
		t.Fatalf("shots %d", len(shots))
	}

	q := shots[0]
	if q.Method != "GET" || q.BodyRaw != "" || q.BodyJson != nil || len(q.BodyForm) != 0 || len(q.Headers) != 1 || !reflect.DeepEqual(q.Headers["Accept"], []string{"text/html"}) {
		t.Fatalf("query shot %#v", q)
	}
	if !reflect.DeepEqual(q.Queries, base.Queries) {
		t.Fatalf("query values %#v", q.Queries)
	}

	form := shots[1]
	if form.Method != "POST" || form.Queries != nil {
		t.Fatalf("form shot method %s queries %#v", form.Method, form.Queries)
	}
	if !reflect.DeepEqual(form.Headers["Content-Type"], []string{"application/x-www-form-urlencoded"}) || !reflect.DeepEqual(form.Headers["Accept"], []string{"text/html"}) {
		t.Fatalf("form headers %#v", form.Headers)
	}
	if !reflect.DeepEqual(form.BodyForm, base.Queries) {
		t.Fatalf("form body %#v", form.BodyForm)
	}

	js := shots[2]
	if js.Method != "POST" || js.Queries != nil || !reflect.DeepEqual(js.Headers["Content-Type"], []string{"application/json"}) {
		t.Fatalf("json shot %#v", js)
	}
	if !reflect.DeepEqual(js.BodyJson, map[string]any{"q": []string{"coffee", "tea"}, "page": "1"}) {
		t.Fatalf("json body %#v", js.BodyJson)
	}

	if !reflect.DeepEqual(base.Queries, map[string][]string{"q": {"coffee", "tea"}, "page": {"1"}}) || base.BodyRaw != "" {
		t.Fatalf("base mutated %#v", base)
	}
}

func TestFuzzInputSourceJSON(t *testing.T) {
	base := Shot{
		Method:  "PUT",
		Headers: map[string][]string{"Content-type": {"application/json"}},
		BodyRaw: `{"name":"ada","n":1,"ok":false,"tags":[1552,261],"child":{"x":"y"}}`,
	}

	shots := FuzzInputSource(base)
	if len(shots) != 3 {
		t.Fatalf("shots %d", len(shots))
	}

	if shots[0].Method != "PUT" || shots[0].BodyRaw != "" || shotHeader(shots[0].Headers, "Content-Type") != "" {
		t.Fatalf("query shot %#v", shots[0])
	}
	if !reflect.DeepEqual(shots[0].Queries, map[string][]string{
		"name":  {"ada"},
		"n":     {"1"},
		"ok":    {"false"},
		"tags":  {"1552", "261"},
		"child": {`{"x":"y"}`},
	}) {
		t.Fatalf("query values %#v", shots[0].Queries)
	}

	if shots[1].Method != "POST" || !reflect.DeepEqual(shots[1].Headers["Content-Type"], []string{"application/x-www-form-urlencoded"}) {
		t.Fatalf("form shot %#v", shots[1])
	}
	if _, ok := shots[1].Headers["Content-type"]; ok {
		t.Fatalf("duplicate content type %#v", shots[1].Headers)
	}
	if !reflect.DeepEqual(shots[1].BodyForm, shots[0].Queries) {
		t.Fatalf("form body %#v", shots[1].BodyForm)
	}

	if shots[2].Method != "POST" || !reflect.DeepEqual(shots[2].Headers["Content-Type"], []string{"application/json"}) {
		t.Fatalf("json shot %#v", shots[2])
	}
	if !reflect.DeepEqual(shots[2].BodyJson, map[string]any{
		"name":  "ada",
		"n":     1,
		"ok":    false,
		"tags":  []any{1552, 261},
		"child": map[string]any{"x": "y"},
	}) {
		t.Fatalf("json body %#v", shots[2].BodyJson)
	}
	if base.BodyRaw == "" || !reflect.DeepEqual(base.Headers["Content-type"], []string{"application/json"}) {
		t.Fatalf("base mutated %#v", base)
	}
}

func TestFuzzInputSourceForm(t *testing.T) {
	base := Shot{
		Method:  "POST",
		Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
		BodyRaw: "name=a+b&id=1&id=2",
	}

	shots := FuzzInputSource(base)
	if shots[0].Method != "POST" || shots[0].BodyRaw != "" {
		t.Fatalf("query shot %#v", shots[0])
	}
	if !reflect.DeepEqual(shots[0].Queries, map[string][]string{"name": {"a b"}, "id": {"1", "2"}}) {
		t.Fatalf("query values %#v", shots[0].Queries)
	}

	if !reflect.DeepEqual(shots[2].BodyJson, map[string]any{"name": "a b", "id": []string{"1", "2"}}) {
		t.Fatalf("json body %#v", shots[2].BodyJson)
	}
}

func TestFuzzInputSourceBodyOverridesQuery(t *testing.T) {
	base := Shot{
		Method:  "POST",
		Headers: map[string][]string{"Content-Type": {"application/json"}},
		Queries: map[string][]string{"id": {"1"}, "page": {"2"}},
		BodyRaw: `{"id":9,"name":"ada"}`,
	}

	shots := FuzzInputSource(base)
	if !reflect.DeepEqual(shots[0].Queries, map[string][]string{"id": {"9"}, "page": {"2"}, "name": {"ada"}}) {
		t.Fatalf("merged %#v", shots[0].Queries)
	}
	if len(shots[1].Queries) != 0 || len(shots[2].Queries) != 0 {
		t.Fatalf("body shots kept queries %#v %#v", shots[1].Queries, shots[2].Queries)
	}
}

func TestFuzzInputSourceUnchanged(t *testing.T) {
	plain := Shot{Method: "POST", BodyRaw: "hello", Headers: map[string][]string{"Content-Type": {"text/plain"}}}
	if got := FuzzInputSource(plain); len(got) != 1 || got[0].BodyRaw != "hello" {
		t.Fatalf("opaque %#v", got)
	}

	array := Shot{Method: "POST", Headers: map[string][]string{"Content-Type": {"application/json"}}, BodyRaw: `[1,2]`}
	if got := FuzzInputSource(array); len(got) != 1 || got[0].BodyRaw != `[1,2]` {
		t.Fatalf("array %#v", got)
	}

	empty := Shot{Method: "GET", Uri: "/health"}
	if got := FuzzInputSource(empty); len(got) != 1 || got[0].Uri != "/health" {
		t.Fatalf("empty %#v", got)
	}
}
