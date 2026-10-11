package fuzz

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
