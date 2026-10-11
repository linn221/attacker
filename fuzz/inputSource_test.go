package fuzz

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
)

func TestFuzzInputSourceQuery(t *testing.T) {
	base := Shot{
		Https:      true,
		DomainName: "example.com",
		Uri:        "/search",
		Method:     "GET",
		Headers:    map[string]string{"Accept": "text/html"},
		Queries:    map[string][]string{"q": {"coffee", "tea"}, "page": {"1"}},
	}

	shots := FuzzInputSource(base)
	if len(shots) != 3 {
		t.Fatalf("shots %d", len(shots))
	}

	q := shots[0]
	if q.Method != "GET" || q.Body != "" || len(q.Headers) != 1 || q.Headers["Accept"] != "text/html" {
		t.Fatalf("query shot %#v", q)
	}
	if !reflect.DeepEqual(q.Queries, base.Queries) {
		t.Fatalf("query values %#v", q.Queries)
	}

	form := shots[1]
	if form.Method != "POST" || form.Queries != nil {
		t.Fatalf("form shot method %s queries %#v", form.Method, form.Queries)
	}
	if form.Headers["Content-Type"] != "application/x-www-form-urlencoded" || form.Headers["Accept"] != "text/html" {
		t.Fatalf("form headers %#v", form.Headers)
	}
	gotForm, err := url.ParseQuery(form.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(map[string][]string(gotForm), base.Queries) {
		t.Fatalf("form body %#v", gotForm)
	}

	js := shots[2]
	if js.Method != "POST" || js.Queries != nil || js.Headers["Content-Type"] != "application/json" {
		t.Fatalf("json shot %#v", js)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(js.Body), &obj); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obj, map[string]any{"q": []any{"coffee", "tea"}, "page": "1"}) {
		t.Fatalf("json body %#v", obj)
	}

	if !reflect.DeepEqual(base.Queries, map[string][]string{"q": {"coffee", "tea"}, "page": {"1"}}) || base.Body != "" {
		t.Fatalf("base mutated %#v", base)
	}
}

func TestFuzzInputSourceJSON(t *testing.T) {
	base := Shot{
		Method:  "PUT",
		Headers: map[string]string{"Content-type": "application/json"},
		Body:    `{"name":"ada","n":1,"ok":false,"tags":[1552,261],"child":{"x":"y"}}`,
	}

	shots := FuzzInputSource(base)
	if len(shots) != 3 {
		t.Fatalf("shots %d", len(shots))
	}

	if shots[0].Method != "PUT" || shots[0].Body != "" || headerValue(shots[0].Headers, "Content-Type") != "" {
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

	if shots[1].Method != "POST" || shots[1].Headers["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Fatalf("form shot %#v", shots[1])
	}
	if _, ok := shots[1].Headers["Content-type"]; ok {
		t.Fatalf("duplicate content type %#v", shots[1].Headers)
	}
	gotForm, err := url.ParseQuery(shots[1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(map[string][]string(gotForm), shots[0].Queries) {
		t.Fatalf("form body %#v", gotForm)
	}

	if shots[2].Method != "POST" || shots[2].Headers["Content-Type"] != "application/json" {
		t.Fatalf("json shot %#v", shots[2])
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(shots[2].Body), &obj); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obj, map[string]any{
		"name":  "ada",
		"n":     float64(1),
		"ok":    false,
		"tags":  []any{float64(1552), float64(261)},
		"child": map[string]any{"x": "y"},
	}) {
		t.Fatalf("json body %s", shots[2].Body)
	}
	if base.Body == "" || base.Headers["Content-type"] != "application/json" {
		t.Fatalf("base mutated %#v", base)
	}
}

func TestFuzzInputSourceForm(t *testing.T) {
	base := Shot{
		Method:  "POST",
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    "name=a+b&id=1&id=2",
	}

	shots := FuzzInputSource(base)
	if shots[0].Method != "POST" || shots[0].Body != "" {
		t.Fatalf("query shot %#v", shots[0])
	}
	if !reflect.DeepEqual(shots[0].Queries, map[string][]string{"name": {"a b"}, "id": {"1", "2"}}) {
		t.Fatalf("query values %#v", shots[0].Queries)
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(shots[2].Body), &obj); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(obj, map[string]any{"name": "a b", "id": []any{"1", "2"}}) {
		t.Fatalf("json body %#v", obj)
	}
}

func TestFuzzInputSourceBodyOverridesQuery(t *testing.T) {
	base := Shot{
		Method:  "POST",
		Headers: map[string]string{"Content-Type": "application/json"},
		Queries: map[string][]string{"id": {"1"}, "page": {"2"}},
		Body:    `{"id":9,"name":"ada"}`,
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
	plain := Shot{Method: "POST", Body: "hello", Headers: map[string]string{"Content-Type": "text/plain"}}
	if got := FuzzInputSource(plain); len(got) != 1 || got[0].Body != "hello" {
		t.Fatalf("opaque %#v", got)
	}

	array := Shot{Method: "POST", Headers: map[string]string{"Content-Type": "application/json"}, Body: `[1,2]`}
	if got := FuzzInputSource(array); len(got) != 1 || got[0].Body != `[1,2]` {
		t.Fatalf("array %#v", got)
	}

	empty := Shot{Method: "GET", Uri: "/health"}
	if got := FuzzInputSource(empty); len(got) != 1 || got[0].Uri != "/health" {
		t.Fatalf("empty %#v", got)
	}
}
