package fuzz

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// inputField is one named parameter carried between input sources.
// values is the query and form representation. When hasRaw is set, raw is the
// original JSON value used for the JSON body.
type inputField struct {
	values []string
	raw    any
	hasRaw bool
}

// FuzzInputSource moves a shot's parameters into each input source: the URL
// query string, a POST form body, and a POST JSON body. Parameters are read
// from the query string, a JSON object body, or a form body. Each result
// carries those parameters in only one source. A shot with no named
// parameters is returned unchanged.
func FuzzInputSource(s Shot) []Shot {
	fields, ok := shotInputFields(s)
	if !ok || len(fields) == 0 {
		return []Shot{s}
	}
	return []Shot{
		shotAsQuery(s, fields),
		shotAsForm(s, fields),
		shotAsJSON(s, fields),
	}
}

func shotInputFields(s Shot) (map[string]inputField, bool) {
	body := strings.TrimSpace(s.Body)
	ct := headerValue(s.Headers, "Content-Type")

	var bodyFields map[string]inputField
	recognized := body == ""
	if body != "" {
		if obj, ok := jsonObjectBody(body, ct); ok {
			recognized = true
			bodyFields = fieldsFromJSONObject(obj)
		} else if form, ok := formInputFields(body, ct); ok {
			recognized = true
			bodyFields = fieldsFromValues(form)
		}
	}
	if !recognized {
		return nil, false
	}

	fields := fieldsFromValues(s.Queries)
	for k, f := range bodyFields {
		fields[k] = f
	}
	return fields, true
}

func jsonObjectBody(body, ct string) (map[string]any, bool) {
	v, ok := decodeJSONBody(body, contentTypeJSON(ct))
	if !ok {
		return nil, false
	}
	obj, ok := v.(map[string]any)
	return obj, ok
}

func formInputFields(body, ct string) (map[string][]string, bool) {
	if contentTypeJSON(ct) {
		return nil, false
	}
	if ct != "" && !contentTypeForm(ct) {
		return nil, false
	}
	if ct == "" && !strings.Contains(body, "=") {
		return nil, false
	}
	return decodeFormBody(body)
}

func fieldsFromValues(m map[string][]string) map[string]inputField {
	fields := make(map[string]inputField, len(m))
	for k, vs := range m {
		if len(vs) == 0 {
			continue
		}
		fields[k] = inputField{values: append([]string(nil), vs...)}
	}
	return fields
}

func fieldsFromJSONObject(obj map[string]any) map[string]inputField {
	fields := make(map[string]inputField, len(obj))
	for k, v := range obj {
		fields[k] = fieldFromJSON(v)
	}
	return fields
}

func fieldFromJSON(v any) inputField {
	if arr, ok := v.([]any); ok && len(arr) > 0 && allJSONScalars(arr) {
		values := make([]string, len(arr))
		for i, item := range arr {
			values[i], _ = jsonScalarString(item)
		}
		return inputField{values: values, raw: v, hasRaw: true}
	}
	if s, ok := jsonScalarString(v); ok {
		return inputField{values: []string{s}, raw: v, hasRaw: true}
	}
	encoded, err := marshalJSON(v)
	if err != nil {
		return inputField{raw: v, hasRaw: true}
	}
	return inputField{values: []string{encoded}, raw: v, hasRaw: true}
}

func allJSONScalars(arr []any) bool {
	for _, item := range arr {
		if _, ok := jsonScalarString(item); !ok {
			return false
		}
	}
	return true
}

func jsonScalarString(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case json.Number:
		return x.String(), true
	default:
		return "", false
	}
}

func shotAsQuery(s Shot, fields map[string]inputField) Shot {
	t := s.Clone()
	t.Queries = fieldValues(fields)
	t.Body = ""
	removeHeader(t.Headers, "Content-Type")
	return t
}

func shotAsForm(s Shot, fields map[string]inputField) Shot {
	t := s.Clone()
	t.Method = "POST"
	t.Queries = nil
	t.Body = encodeFormFields(fields)
	t.Headers = replaceHeader(t.Headers, "Content-Type", "application/x-www-form-urlencoded")
	return t
}

func shotAsJSON(s Shot, fields map[string]inputField) Shot {
	t := s.Clone()
	t.Method = "POST"
	t.Queries = nil
	t.Body = encodeJSONFields(fields)
	t.Headers = replaceHeader(t.Headers, "Content-Type", "application/json")
	return t
}

func fieldValues(fields map[string]inputField) map[string][]string {
	out := make(map[string][]string, len(fields))
	for k, f := range fields {
		if len(f.values) == 0 {
			continue
		}
		out[k] = append([]string(nil), f.values...)
	}
	return out
}

func encodeFormFields(fields map[string]inputField) string {
	v := make(url.Values, len(fields))
	for k, f := range fields {
		for _, value := range f.values {
			v.Add(k, value)
		}
	}
	return v.Encode()
}

func encodeJSONFields(fields map[string]inputField) string {
	obj := make(map[string]any, len(fields))
	for k, f := range fields {
		switch {
		case f.hasRaw:
			obj[k] = f.raw
		case len(f.values) == 1:
			obj[k] = f.values[0]
		default:
			obj[k] = append([]string(nil), f.values...)
		}
	}
	encoded, err := marshalJSON(obj)
	if err != nil {
		return ""
	}
	return encoded
}

func marshalJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func replaceHeader(h map[string]string, name, value string) map[string]string {
	if h == nil {
		h = make(map[string]string)
	}
	removeHeader(h, name)
	h[name] = value
	return h
}

func removeHeader(h map[string]string, name string) {
	for k := range h {
		if strings.EqualFold(k, name) {
			delete(h, k)
		}
	}
}
