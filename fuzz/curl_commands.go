package fuzz

import (
	"fmt"
	"strings"
)

// ParseCurlCommands reads shell text, skips everything that is not a curl
// command, and parses each curl command into a Configuration.
// A curl command that cannot be parsed is reported in the returned errors
// and left out of the configuration slice.
func ParseCurlCommands(text string) ([]Configuration, []error) {
	var cfgs []Configuration
	var errs []error
	for _, cmd := range splitShellCommands(text) {
		words, err := splitShell(cmd)
		if err != nil {
			if isCurlCommand(cmd) {
				errs = append(errs, fmt.Errorf("%s: %w", abbreviateCommand(cmd), err))
			}
			continue
		}
		words = trimCommandPrefix(words)
		if len(words) == 0 || !isCurlArgv0(words[0]) {
			continue
		}
		cfg, err := ParseCurl(shellJoin(words))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", abbreviateCommand(cmd), err))
			continue
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs, errs
}

func shellJoin(words []string) string {
	quoted := make([]string, len(words))
	for i, word := range words {
		quoted[i] = "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func trimCommandPrefix(words []string) []string {
	for len(words) > 0 && (words[0] == "$" || isEnvAssign(words[0])) {
		words = words[1:]
	}
	return words
}

func isEnvAssign(word string) bool {
	if word == "" || !isNameStart(word[0]) {
		return false
	}
	for i := 1; i < len(word); i++ {
		if word[i] == '=' {
			return true
		}
		if !isNameStart(word[i]) && (word[i] < '0' || word[i] > '9') {
			return false
		}
	}
	return false
}

func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isCurlCommand(cmd string) bool {
	for _, field := range strings.Fields(cmd) {
		if field == "$" || isEnvAssign(field) {
			continue
		}
		return isCurlArgv0(strings.Trim(field, `"'`))
	}
	return false
}

func abbreviateCommand(cmd string) string {
	s := strings.Join(strings.Fields(cmd), " ")
	const max = 80
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

func splitShellCommands(s string) []string {
	var cmds []string
	var buf strings.Builder
	var quote byte
	inToken := false

	flush := func() {
		cmd := strings.TrimSpace(buf.String())
		buf.Reset()
		inToken = false
		if cmd != "" {
			cmds = append(cmds, cmd)
		}
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == '\'' {
			buf.WriteByte(c)
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			buf.WriteByte(c)
			if c == '\\' && i+1 < len(s) {
				i++
				buf.WriteByte(s[i])
				continue
			}
			if c == '"' {
				quote = 0
			}
			continue
		}

		if c == '\\' {
			if i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\r') {
				buf.WriteByte('\\')
				buf.WriteByte(s[i+1])
				i++
				if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
					i++
					buf.WriteByte('\n')
				}
				continue
			}
			buf.WriteByte('\\')
			if i+1 < len(s) {
				i++
				buf.WriteByte(s[i])
			}
			inToken = true
			continue
		}

		if c == '\'' || c == '"' {
			quote = c
			buf.WriteByte(c)
			inToken = true
			continue
		}
		if c == '#' && !inToken {
			for i+1 < len(s) && s[i+1] != '\n' && s[i+1] != '\r' {
				i++
			}
			continue
		}
		if c == '\n' {
			flush()
			continue
		}
		if c == '\r' {
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			flush()
			continue
		}
		if c == ';' || c == '|' || c == '&' || c == '<' || c == '>' {
			if (c == '|' || c == '&' || c == '>') && i+1 < len(s) && s[i+1] == c {
				i++
			}
			if c == '>' || c == '<' {
				trimTrailingFD(&buf)
			}
			flush()
			continue
		}
		if c == ' ' || c == '\t' {
			buf.WriteByte(c)
			inToken = false
			continue
		}
		buf.WriteByte(c)
		inToken = true
	}
	flush()
	return cmds
}

func trimTrailingFD(buf *strings.Builder) {
	s := buf.String()
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) || (i > 0 && (s[i-1] != ' ' && s[i-1] != '\t')) {
		return
	}
	buf.Reset()
	buf.WriteString(s[:i])
}
