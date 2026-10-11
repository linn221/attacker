package fuzz

func TryAccepts(s Shot) []Shot {
	values := []string{
		// HTML
		"text/html",
		"application/xhtml+xml",
		"text/html,application/xhtml+xml",

		// JSON / APIs
		"application/json",
		"application/*+json",
		"application/json,text/plain,*/*",

		// XML
		"application/xml",
		"text/xml",
		"application/xml,text/xml",

		// Plain / generic
		"text/plain",
		"*/*",

		// Common browser-style combinations
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Accept"] = []string{v}
		return s
	})(s)
}

func TryUserAgent(s Shot) []Shot {
	values := []string{
		// Generic
		"Mozilla/5.0",
		"curl/8.0.0",
		"Wget/1.21.4",

		// iPhone / iOS Safari
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",

		// Android Chrome
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",

		// Android generic
		"Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",

		// Desktop Chrome
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

		// Firefox
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",

		// Safari / macOS
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",

		// Googlebot
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",

		// Bingbot
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",

		// Facebook crawler
		"facebookexternalhit/1.1",

		// Twitter crawler
		"Twitterbot/1.0",

		// Google mobile crawler
		"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5 Build/MOB30J) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["User-Agent"] = []string{v}
		return s
	})(s)
}

func TryReferer(s Shot) []Shot {
	values := []string{
		// Search engines
		"https://www.google.com/",
		"https://www.google.com/search?q=test",
		"https://www.bing.com/",
		"https://search.yahoo.com/",
		"https://duckduckgo.com/",

		// Social media
		"https://www.facebook.com/",
		"https://www.instagram.com/",
		"https://twitter.com/",
		"https://x.com/",
		"https://www.linkedin.com/",
		"https://www.reddit.com/",

		// Common referrers
		"https://example.com/",
		"http://example.com/",

		// Same-origin-ish paths
		"/",
		"/login",
		"/register",
		"/admin",
		"/dashboard",

		// Empty / unusual
		"",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Referer"] = []string{v}
		return s
	})(s)
}

func TryAcceptLanguage(s Shot) []Shot {
	values := []string{
		"en",
		"en-US",
		"en-GB",
		"my",
		"my-MM",
		"zh",
		"ja",
		"ko",
		"de",
		"fr",
		"es",
		"en-US,en;q=0.9",
		"en-US,en;q=0.9,my;q=0.8",
		"*",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Accept-Language"] = []string{v}
		return s
	})(s)
}

func TryAcceptEncoding(s Shot) []Shot {
	values := []string{
		"gzip",
		"deflate",
		"br",
		"gzip, deflate",
		"gzip, deflate, br",
		"identity",
		"*",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Accept-Encoding"] = []string{v}
		return s
	})(s)
}

func HostHeaderInjection(s Shot) []Shot {

	hosts := []string{

		"",
		"null",

		"http://example.com",
		"https://example.com",

		"http://localhost",
		"https://localhost",

		"http://127.0.0.1",
		"https://127.0.0.1",
		"127.0.0.1",
		"8.8.8.8",

		"http://localhost:3000",
		"http://localhost:5173",
		"http://localhost:8080",

		"https://www.google.com",
		"https://www.facebook.com",
	}

	return vary(hosts, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Host"] = []string{v}

		return s
	})(s)
}
func TryOrigin(s Shot) []Shot {
	values := []string{
		"",
		"null",

		"http://example.com",
		"https://example.com",

		"http://localhost",
		"https://localhost",

		"http://127.0.0.1",
		"https://127.0.0.1",

		"http://localhost:3000",
		"http://localhost:5173",
		"http://localhost:8080",

		"https://www.google.com",
		"https://www.facebook.com",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Origin"] = []string{v}

		return s
	})(s)
}

func TryContentType(s Shot) []Shot {
	values := []string{
		"application/json",
		"application/json; charset=utf-8",

		"application/x-www-form-urlencoded",

		"multipart/form-data",

		"text/plain",
		"text/plain; charset=utf-8",

		"application/xml",
		"text/xml",

		"application/graphql",

		"application/octet-stream",

		"application/x-www-form-urlencoded; charset=UTF-8",

		"application/vnd.api+json",
		"application/hal+json",
		"application/problem+json",
		"application/*+json",
	}

	return vary(values, func(s Shot, v string) Shot {
		if s.Headers == nil {
			s.Headers = make(map[string][]string)
		}

		s.Headers["Content-Type"] = []string{v}

		return s
	})(s)
}

func TryAjax(s Shot) []Shot {
	shots := make([]Shot, 0, 10)

	// XMLHttpRequest / jQuery
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+1)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["X-Requested-With"] = []string{"XMLHttpRequest"}

		shots = append(shots, shot)
	}

	// Fetch API
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+2)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["Sec-Fetch-Mode"] = []string{"cors"}
		shot.Headers["Sec-Fetch-Dest"] = []string{"empty"}

		shots = append(shots, shot)
	}

	// Fetch API with JSON expectation
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+3)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["Sec-Fetch-Mode"] = []string{"cors"}
		shot.Headers["Sec-Fetch-Dest"] = []string{"empty"}
		shot.Headers["Accept"] = []string{"application/json"}

		shots = append(shots, shot)
	}

	// Flutter / Dart HTTP client
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+2)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["User-Agent"] = []string{"Dart/3.0 (dart:io)"}
		shot.Headers["Accept"] = []string{"application/json"}

		shots = append(shots, shot)
	}

	// Flutter application request
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+3)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["User-Agent"] = []string{"Dart/3.0 (dart:io)"}
		shot.Headers["Accept"] = []string{"application/json"}
		shot.Headers["Content-Type"] = []string{"application/json"}

		shots = append(shots, shot)
	}

	// Axios-like request
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+1)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["Accept"] = []string{"application/json, text/plain, */*"}

		shots = append(shots, shot)
	}

	// jQuery AJAX JSON request
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+2)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["X-Requested-With"] = []string{"XMLHttpRequest"}
		shot.Headers["Accept"] = []string{"application/json, text/javascript, */*; q=0.01"}

		shots = append(shots, shot)
	}

	// GraphQL-style client
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+2)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["Accept"] = []string{"application/json"}
		shot.Headers["Content-Type"] = []string{"application/json"}

		shots = append(shots, shot)
	}

	// Browser navigation
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+3)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["Sec-Fetch-Mode"] = []string{"navigate"}
		shot.Headers["Sec-Fetch-Dest"] = []string{"document"}
		shot.Headers["Sec-Fetch-User"] = []string{"?1"}

		shots = append(shots, shot)
	}

	// Mobile application
	{
		shot := s
		shot.Headers = make(map[string][]string, len(s.Headers)+2)
		for k, v := range s.Headers {
			shot.Headers[k] = append([]string(nil), v...)
		}
		shot.Headers["User-Agent"] = []string{"Dart/3.0 (dart:io)"}
		shot.Headers["Accept"] = []string{"*/*"}

		shots = append(shots, shot)
	}

	return shots
}
