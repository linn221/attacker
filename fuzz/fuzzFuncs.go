package fuzz

import "strings"

func ToggleHttps(base Shot) []Shot {
	shots := make([]Shot, 2)
	shots[0] = base.Clone()
	shots[1] = base.Clone()
	shots[0].Https = true
	shots[1].Https = false
	return shots
}

func vary(values []string, apply func(s Shot, v string) Shot) FuzzFunc {
	return func(base Shot) []Shot {
		shots := make([]Shot, 0, len(values))
		for _, v := range values {
			shots = append(shots, apply(base.Clone(), v))
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

func AppendExtension(s Shot) []Shot {
	extensions := []string{
		// PHP
		".php",
		".php3",
		".php4",
		".php5",
		".php7",
		".php8",
		".phtml",

		// ASP / ASP.NET
		".asp",
		".aspx",
		".ashx",
		".asmx",
		".asax",
		".axd",
		".svc",

		// JSP / Java web
		".jsp",
		".jspx",
		".do",
		".action",
		".faces",

		// ColdFusion
		".cfm",
		".cfml",

		// CGI
		".cgi",

		// Perl CGI
		".pl",

		// Static web documents
		".html",
		".htm",
		".xhtml",
		".shtml",
	}

	return vary(extensions, func(s Shot, extension string) Shot {
		if i := strings.IndexByte(s.Uri, '?'); i >= 0 {
			s.Uri = s.Uri[:i] + extension + s.Uri[i:]
		} else {
			s.Uri += extension
		}

		return s
	})(s)
}
