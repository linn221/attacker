package fuzz

func ToggleHttps(base Shot) []Shot {
	shots := make([]Shot, 2)
	shots[0] = base.Clone()
	shots[1] = base.Clone()
	shots[0].Https = true
	shots[1].Https = false
	return shots
}

func vary(values []string, apply func(s Shot, v string) Shot) FuzzFunc {
	return func(s Shot) []Shot {
		shots := make([]Shot, 0, len(values))
		for _, v := range values {
			shots = append(shots, apply(s, v))
		}
		return shots
	}
}

func AddCookies(name string, values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Cookies = cloneValues(s.Cookies)
		s.Cookies[name] = []string{v}
		return s
	})
}

func AppendCookies(name string, values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Cookies = cloneValues(s.Cookies)
		s.Cookies[name] = append(s.Cookies[name], v)
		return s
	})
}

func AddHeader(name string, values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Headers = cloneHeaders(s.Headers)
		s.Headers[name] = v
		return s
	})
}

func AppendHeader(name string, values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Headers = cloneHeaders(s.Headers)
		if cur := s.Headers[name]; cur != "" {
			s.Headers[name] = cur + ", " + v
		} else {
			s.Headers[name] = v
		}
		return s
	})
}

func AddQuery(name string, values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Queries = cloneValues(s.Queries)
		s.Queries[name] = []string{v}
		return s
	})
}

func AppendQuery(name string, values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Queries = cloneValues(s.Queries)
		s.Queries[name] = append(s.Queries[name], v)
		return s
	})
}

func AllMethods() FuzzFunc {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD"}
	return func(s Shot) []Shot {
		shots := make([]Shot, 0, len(methods))
		for _, method := range methods {
			t := s.Clone()
			t.Method = method
			shots = append(shots, t)
		}

		return shots
	}
}

func Subdomains(values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.DomainName = v
		return s
	})
}

func Uri(values ...string) FuzzFunc {
	return vary(values, func(s Shot, v string) Shot {
		s.Uri = v
		return s
	})
}

func ParameterPollutionQuery(name string, value string) FuzzFunc {
	return func(s Shot) []Shot {
		next := s
		next.Queries = cloneValues(s.Queries)
		next.Queries[name] = append(next.Queries[name], value)
		return []Shot{s, next}
	}
}

func ReadWordlist(file string) []string {

	panic("//implement")
}
