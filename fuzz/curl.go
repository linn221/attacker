package fuzz

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path"
	"strings"
)

// ParseCurl converts a curl command into a Configuration.
// The command may include a leading curl path. Flags that do not change the
// request itself, such as --compressed or --silent, are ignored.
func ParseCurl(command string) (Configuration, error) {
	words, err := splitShell(command)
	if err != nil {
		return Configuration{}, err
	}
	if len(words) > 0 && words[0] == "$" {
		words = words[1:]
	}
	if len(words) > 0 && isCurlArgv0(words[0]) {
		words = words[1:]
	}
	if len(words) == 0 {
		return Configuration{}, fmt.Errorf("empty curl command")
	}

	st := curlState{}
	for i := 0; i < len(words); {
		word := words[i]
		if word == "--" {
			for _, raw := range words[i+1:] {
				if err := st.setURL(raw); err != nil {
					return Configuration{}, err
				}
			}
			break
		}
		if isCurlOption(word) {
			opts, next, err := parseCurlOptions(words, i)
			if err != nil {
				return Configuration{}, err
			}
			for _, opt := range opts {
				if err := st.apply(opt); err != nil {
					return Configuration{}, err
				}
			}
			i = next
			continue
		}
		if err := st.setURL(word); err != nil {
			return Configuration{}, err
		}
		i++
	}
	return st.finish()
}

type curlState struct {
	cfg       Configuration
	method    string
	methodSet bool
	head      bool
	useGet    bool
	sawData   bool
	sawJSON   bool
	bodyParts []string
	haveURL   bool
}

type curlOption struct {
	name string
	val  string
}

func (st *curlState) apply(opt curlOption) error {
	switch opt.name {
	case "request":
		st.method = opt.val
		st.methodSet = true
	case "header":
		return addHeaderLine(&st.cfg, opt.val)
	case "data", "data-raw", "data-binary", "data-ascii", "data-urlencode", "json":
		part, err := curlBody(opt.name, opt.val)
		if err != nil {
			return err
		}
		st.sawData = true
		if opt.name == "json" {
			st.sawJSON = true
		}
		st.bodyParts = append(st.bodyParts, part)
	case "cookie":
		if !strings.Contains(opt.val, "=") {
			return fmt.Errorf("cookie jar files are not supported")
		}
		addCookieString(&st.cfg, opt.val)
	case "user-agent":
		setHeader(&st.cfg, "User-Agent", opt.val)
	case "referer":
		setHeader(&st.cfg, "Referer", opt.val)
	case "user":
		user := opt.val
		if !strings.Contains(user, ":") {
			user += ":"
		}
		setHeader(&st.cfg, "Authorization", basicAuth(user))
	case "url":
		return st.setURL(opt.val)
	case "get":
		st.useGet = true
	case "head":
		st.head = true
	}
	return nil
}

func (st *curlState) setURL(raw string) error {
	if st.haveURL {
		return fmt.Errorf("curl command contains multiple urls")
	}
	if raw == "-" {
		return fmt.Errorf("reading the curl url from stdin is not supported")
	}
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("curl command is missing a url")
	}

	parsed := raw
	if !hasURLScheme(parsed) {
		parsed = "http://" + parsed
	}
	u, err := url.Parse(parsed)
	if err != nil {
		return fmt.Errorf("parse curl url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("parse curl url: missing host in %q", raw)
	}

	https := strings.EqualFold(u.Scheme, "https")
	host := u.Host
	uri := u.Path
	if uri == "" {
		uri = "/"
	}
	st.cfg.Https = &https
	st.cfg.DomainName = &host
	st.cfg.Uri = &uri

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return fmt.Errorf("parse curl query: %w", err)
	}
	addQueries(&st.cfg, q)

	if u.User != nil && !headerSet(st.cfg.Headers, "Authorization") {
		pass, ok := u.User.Password()
		if !ok {
			pass = ""
		}
		setHeader(&st.cfg, "Authorization", basicAuth(u.User.Username()+":"+pass))
	}
	st.haveURL = true
	return nil
}

func (st *curlState) finish() (Configuration, error) {
	if !st.haveURL {
		return Configuration{}, fmt.Errorf("curl command is missing a url")
	}

	method := "GET"
	switch {
	case st.methodSet:
		method = strings.ToUpper(st.method)
	case st.head:
		method = "HEAD"
	case st.sawData && !st.useGet:
		method = "POST"
	}
	st.cfg.Method = &method

	if st.sawData && st.useGet {
		joined := strings.Join(st.bodyParts, "&")
		if joined != "" {
			q, err := url.ParseQuery(joined)
			if err != nil {
				return Configuration{}, fmt.Errorf("parse curl data as query: %w", err)
			}
			addQueries(&st.cfg, q)
		}
		return st.cfg, nil
	}
	if st.sawData {
		body := strings.Join(st.bodyParts, "&")
		st.cfg.Body = &body
		if st.sawJSON {
			if !headerSet(st.cfg.Headers, "Content-Type") {
				setHeader(&st.cfg, "Content-Type", "application/json")
			}
			if !headerSet(st.cfg.Headers, "Accept") {
				setHeader(&st.cfg, "Accept", "application/json")
			}
		} else if !headerSet(st.cfg.Headers, "Content-Type") {
			setHeader(&st.cfg, "Content-Type", "application/x-www-form-urlencoded")
		}
		noteStructuredBody(&st.cfg, body, st.sawJSON)
	}
	return st.cfg, nil
}

// noteStructuredBody records Body as BodyJson or BodyForm when it parses.
// Body itself is left unchanged. JSON wins when the text is a JSON object or
// array, and also when the content type or --json flag says the body is JSON.
func noteStructuredBody(cfg *Configuration, body string, sawJSON bool) {
	ct := headerValue(cfg.Headers, "Content-Type")
	asJSON := sawJSON || contentTypeJSON(ct)
	if v, ok := decodeJSONBody(body, asJSON); ok {
		cfg.BodyJson = v
		return
	}
	if contentTypeForm(ct) {
		if form, ok := decodeFormBody(body); ok {
			cfg.BodyForm = form
		}
	}
}

func decodeJSONBody(body string, force bool) (any, bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, false
	}
	if !force && trimmed[0] != '{' && trimmed[0] != '[' {
		return nil, false
	}
	if !json.Valid([]byte(trimmed)) {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return normalizeJSON(v), true
}

func normalizeJSON(v any) any {
	switch x := v.(type) {
	case json.Number:
		return normalizeJSONNumber(x)
	case map[string]any:
		for k, val := range x {
			x[k] = normalizeJSON(val)
		}
		return x
	case []any:
		for i, val := range x {
			x[i] = normalizeJSON(val)
		}
		return x
	default:
		return v
	}
}

func normalizeJSONNumber(n json.Number) any {
	if i, err := n.Int64(); err == nil {
		if int64(int(i)) == i {
			return int(i)
		}
		return i
	}
	if f, err := n.Float64(); err == nil {
		return f
	}
	return n.String()
}

func decodeFormBody(body string) (map[string][]string, bool) {
	v, err := url.ParseQuery(body)
	if err != nil || len(v) == 0 {
		return nil, false
	}
	return v, true
}

func headerValue(h map[string]string, name string) string {
	for key, value := range h {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func contentTypeJSON(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	mt = strings.ToLower(mt)
	return mt == "application/json" || strings.HasSuffix(mt, "+json")
}

func contentTypeForm(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return strings.EqualFold(mt, "application/x-www-form-urlencoded")
}

func addHeaderLine(cfg *Configuration, line string) error {
	name, value, ok := splitHeader(line)
	if !ok {
		return fmt.Errorf("invalid curl header %q", line)
	}
	setHeader(cfg, name, value)
	return nil
}

func setHeader(cfg *Configuration, name, value string) {
	if strings.EqualFold(name, "Cookie") {
		addCookieString(cfg, value)
		return
	}
	if skipGeneratedHeader(name) {
		return
	}
	if cfg.Headers == nil {
		cfg.Headers = make(map[string]string)
	}
	cfg.Headers[name] = value
}

// skipGeneratedHeader drops headers that a browser adds to every request and
// that do not describe the call: connection management and cache validators.
func skipGeneratedHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding",
		"cache-control", "pragma", "expires",
		"if-modified-since", "if-none-match", "if-match", "if-unmodified-since", "if-range",
		"accept-encoding", "priority", "alt-used", "upgrade-insecure-requests",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
		"access-control-allow-origin":
		return true
	default:
		return false
	}
}

func addCookieString(cfg *Configuration, s string) {
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if cfg.Cookies == nil {
			cfg.Cookies = make(map[string]string)
		}
		cfg.Cookies[name] = value
	}
}

func addQueries(cfg *Configuration, v url.Values) {
	if len(v) == 0 {
		return
	}
	if cfg.Queries == nil {
		cfg.Queries = make(map[string][]string, len(v))
	}
	for key, vals := range v {
		cfg.Queries[key] = append(cfg.Queries[key], vals...)
	}
}

func splitHeader(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		if strings.HasSuffix(line, ";") {
			name = strings.TrimSpace(strings.TrimSuffix(line, ";"))
			if name == "" {
				return "", "", false
			}
			return name, "", true
		}
		return "", "", false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}
	return name, strings.TrimSpace(value), true
}

func headerSet(h map[string]string, name string) bool {
	for key := range h {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func basicAuth(userpass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass))
}

func curlBody(kind, value string) (string, error) {
	switch kind {
	case "data-raw", "json":
		return value, nil
	case "data-urlencode":
		return encodeDataURL(value)
	case "data", "data-ascii", "data-binary":
		if !strings.HasPrefix(value, "@") {
			return value, nil
		}
		file := strings.TrimPrefix(value, "@")
		if file == "-" {
			return "", fmt.Errorf("reading curl data from stdin is not supported")
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read curl data file %s: %w", file, err)
		}
		s := string(b)
		if kind != "data-binary" {
			s = strings.NewReplacer("\r", "", "\n", "").Replace(s)
		}
		return s, nil
	default:
		return value, nil
	}
}

func encodeDataURL(value string) (string, error) {
	if strings.HasPrefix(value, "=") {
		return curlEscape(value[1:]), nil
	}
	if name, content, ok := strings.Cut(value, "="); ok {
		return name + "=" + curlEscape(content), nil
	}
	if name, file, ok := strings.Cut(value, "@"); ok {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read curl data file %s: %w", file, err)
		}
		enc := curlEscape(string(b))
		if name == "" {
			return enc, nil
		}
		return name + "=" + enc, nil
	}
	return curlEscape(value), nil
}

func curlEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func isCurlArgv0(word string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(word, "\\", "/")))
	return base == "curl" || base == "curl.exe"
}

func isCurlOption(word string) bool {
	return strings.HasPrefix(word, "-") && len(word) > 1
}

func hasURLScheme(raw string) bool {
	i := strings.Index(raw, "://")
	if i <= 0 {
		return false
	}
	for _, c := range raw[:i] {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

type curlOptClass int

const (
	curlOptUnknown curlOptClass = iota
	curlOptBool
	curlOptArg
	curlOptIgnore
	curlOptReject
)

func parseCurlOptions(words []string, i int) ([]curlOption, int, error) {
	word := words[i]
	if strings.HasPrefix(word, "--") {
		return parseLongOption(words, i)
	}
	return parseShortOptions(words, i)
}

func parseLongOption(words []string, i int) ([]curlOption, int, error) {
	body := strings.TrimPrefix(words[i], "--")
	name, inline, hasInline := strings.Cut(body, "=")
	name = aliasCurlOption(name)
	switch classifyCurlOption(name) {
	case curlOptBool:
		if hasInline {
			return nil, 0, fmt.Errorf("curl option --%s does not take a value", name)
		}
		return []curlOption{{name: name}}, i + 1, nil
	case curlOptArg, curlOptIgnore:
		val, next, err := curlOptionValue(words, i, inline, hasInline, "--"+name)
		if err != nil {
			return nil, 0, err
		}
		if classifyCurlOption(name) == curlOptIgnore {
			return nil, next, nil
		}
		return []curlOption{{name: name, val: val}}, next, nil
	case curlOptReject:
		return nil, 0, fmt.Errorf("unsupported curl option --%s", name)
	default:
		return nil, 0, fmt.Errorf("unsupported curl option --%s", name)
	}
}

func parseShortOptions(words []string, i int) ([]curlOption, int, error) {
	cluster := words[i][1:]
	var opts []curlOption
	for j := 0; j < len(cluster); j++ {
		letter := cluster[j]
		name, ok := shortCurlOption[letter]
		if !ok {
			return nil, 0, fmt.Errorf("unsupported curl option -%s", string(letter))
		}
		name = aliasCurlOption(name)
		switch classifyCurlOption(name) {
		case curlOptBool:
			opts = append(opts, curlOption{name: name})
		case curlOptArg, curlOptIgnore:
			rest := cluster[j+1:]
			val := rest
			next := i + 1
			inline := rest != ""
			if !inline {
				var err error
				val, next, err = curlOptionValue(words, i, "", false, "-"+string(letter))
				if err != nil {
					return nil, 0, err
				}
			}
			if classifyCurlOption(name) != curlOptIgnore {
				opts = append(opts, curlOption{name: name, val: val})
			}
			return opts, next, nil
		case curlOptReject:
			return nil, 0, fmt.Errorf("unsupported curl option -%s", string(letter))
		default:
			return nil, 0, fmt.Errorf("unsupported curl option -%s", string(letter))
		}
	}
	return opts, i + 1, nil
}

func curlOptionValue(words []string, i int, inline string, hasInline bool, label string) (string, int, error) {
	if hasInline {
		return inline, i + 1, nil
	}
	if i+1 >= len(words) {
		return "", 0, fmt.Errorf("curl option %s requires a value", label)
	}
	return words[i+1], i + 2, nil
}

func aliasCurlOption(name string) string {
	if name == "referrer" {
		return "referer"
	}
	return name
}

var shortCurlOption = map[byte]string{
	'X': "request",
	'H': "header",
	'd': "data",
	'b': "cookie",
	'A': "user-agent",
	'e': "referer",
	'u': "user",
	'G': "get",
	'I': "head",
	's': "silent",
	'S': "show-error",
	'k': "insecure",
	'L': "location",
	'v': "verbose",
	'i': "include",
	'f': "fail",
	'g': "globoff",
	'#': "progress-bar",
	'n': "netrc",
	'4': "ipv4",
	'6': "ipv6",
	'0': "http1.0",
	'm': "max-time",
	'o': "output",
	'w': "write-out",
	'x': "proxy",
	'E': "cert",
	'D': "dump-header",
	'c': "cookie-jar",
	'r': "range",
	'C': "continue-at",
	'z': "time-cond",
	'Y': "speed-limit",
	'y': "speed-time",
	'F': "form",
	'T': "upload-file",
	'K': "config",
	'U': "proxy-user",
}

func classifyCurlOption(name string) curlOptClass {
	switch name {
	case "request", "header", "data", "data-raw", "data-binary", "data-ascii", "data-urlencode", "json",
		"cookie", "user-agent", "referer", "user", "url":
		return curlOptArg
	case "get", "head",
		"silent", "show-error", "insecure", "location", "verbose", "include", "fail", "fail-with-body",
		"compressed", "progress-bar", "raw", "globoff", "path-as-is", "junk-session-cookies",
		"location-trusted", "netrc", "netrc-optional", "remote-header-name",
		"post301", "post302", "post303",
		"http1.0", "http1.1", "http2", "http2-prior-knowledge", "http3",
		"ipv4", "ipv6", "no-progress-meter", "no-buffer", "buffer",
		"proxytunnel", "tcp-nodelay", "tr-encoding", "crlf",
		"ssl", "ssl-reqd", "tlsv1", "tlsv1.0", "tlsv1.1", "tlsv1.2", "tlsv1.3",
		"anyauth", "basic", "digest", "negotiate", "ntlm",
		"no-keepalive", "no-alpn", "no-sessionid", "false-start":
		return curlOptBool
	case "output", "max-time", "connect-timeout", "write-out", "retry", "retry-delay", "retry-max-time",
		"proxy", "resolve", "connect-to", "cert", "key", "cacert", "capath",
		"trace", "trace-ascii", "cookie-jar", "dump-header", "output-dir",
		"limit-rate", "speed-limit", "speed-time", "keepalive-time", "max-redirs",
		"stderr", "unix-socket", "abstract-unix-socket", "ciphers", "tls13-ciphers",
		"pinnedpubkey", "libcurl", "interface", "max-filesize", "range", "continue-at",
		"time-cond", "proxy-user", "proxy-header", "noproxy", "doh-url", "dns-servers",
		"expect100-timeout", "happy-eyeballs-timeout-ms", "local-port", "alt-svc", "hsts",
		"crlfile", "engine", "aws-sigv4", "variable", "proto", "proto-default", "proto-redir":
		return curlOptIgnore
	case "form", "upload-file", "config":
		return curlOptReject
	default:
		return curlOptUnknown
	}
}

func splitShell(s string) ([]string, error) {
	var tokens []string
	var buf strings.Builder
	inToken := false
	var quote byte

	flush := func() {
		tokens = append(tokens, buf.String())
		buf.Reset()
		inToken = false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
				continue
			}
			buf.WriteByte(c)
			continue
		}
		if quote == '"' {
			if c == '\\' && i+1 < len(s) {
				next := s[i+1]
				if next == '\r' && i+2 < len(s) && s[i+2] == '\n' {
					i += 2
					continue
				}
				switch next {
				case '"', '\\', '$', '`', '\n', '\r':
					if next != '\n' && next != '\r' {
						buf.WriteByte(next)
					}
					i++
					continue
				}
			}
			if c == '"' {
				quote = 0
				continue
			}
			buf.WriteByte(c)
			continue
		}

		if c == '\\' {
			if i+1 >= len(s) {
				return nil, fmt.Errorf("unterminated escape in curl command")
			}
			next := s[i+1]
			if next == '\r' && i+2 < len(s) && s[i+2] == '\n' {
				i += 2
				continue
			}
			if next == '\n' || next == '\r' {
				i++
				continue
			}
			buf.WriteByte(next)
			i++
			inToken = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			inToken = true
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if inToken {
				flush()
			}
			continue
		}
		buf.WriteByte(c)
		inToken = true
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in curl command")
	}
	if inToken {
		flush()
	}
	return tokens, nil
}
