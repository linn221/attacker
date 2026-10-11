package finding

import (
	"regexp"

	"github.com/linn221/attacker/models"
)

type errorRule struct {
	name        string
	severity    string
	description string
	pattern     *regexp.Regexp
}

var errorRules = []errorRule{
	{
		name:        "error-message",
		severity:    "low",
		description: "Possible error message exposed in response",
		pattern: regexp.MustCompile(
			`(?i)\b(?:fatal\s+)?error\s*:\s*\S`,
		),
	},
	{
		name:        "exception",
		severity:    "medium",
		description: "Possible exception or runtime error exposed",
		pattern: regexp.MustCompile(
			`(?i)\b[A-Za-z_][\w.$]*(?:Exception|Error)\b`,
		),
	},
	{
		name:        "syntax-error",
		severity:    "medium",
		description: "Possible syntax or parsing error exposed",
		pattern: regexp.MustCompile(
			`(?i)\b(?:syntax error|invalid syntax|unexpected token|` +
				`unexpected end of input|unterminated string)\b`,
		),
	},
	{
		name:        "stack-trace",
		severity:    "high",
		description: "Possible stack trace exposed in response",
		pattern: regexp.MustCompile(
			`(?m)^\s*(?:goroutine \d+ \[.+\]:|` +
				`at\s+[\w.$<>]+\s*\(|` +
				`File "[^"]+", line \d+|` +
				`Traceback \(most recent call last\):)`,
		),
	},
	{
		name:        "source-location",
		severity:    "medium",
		description: "Possible source code path and line number exposed",
		pattern: regexp.MustCompile(
			`(?i)(?:/[^\s"'<>:]+|[A-Za-z]:\\[^\s"'<>]+)\.(?:go|php|py|js|ts|java|rb|cs):\d+`,
		),
	},
	{
		name:        "database-error",
		severity:    "medium",
		description: "Possible database error or query diagnostic exposed",
		pattern: regexp.MustCompile(
			`(?i)\b(?:SQLSTATE|SQLException|PDOException|` +
				`ODBC Driver|SQL syntax|query failed|` +
				`database error|unknown column|no such table|` +
				`unterminated quoted string)\b`,
		),
	},
	{
		name:        "runtime-error",
		severity:    "medium",
		description: "Possible runtime error or uncaught exception exposed",
		pattern: regexp.MustCompile(
			`(?i)\b(?:uncaught exception|unhandled exception|` +
				`nil pointer dereference|null pointer exception|` +
				`segmentation fault|stack overflow|` +
				`undefined variable|undefined method|` +
				`index out of range|division by zero)\b`,
		),
	},
	{
		name:        "internal-error",
		severity:    "low",
		description: "Possible internal application error exposed",
		pattern: regexp.MustCompile(
			`(?i)\b(?:internal server error|internal server exception|` +
				`failed to execute|failed to compile|` +
				`failed to parse|compilation failed)\b`,
		),
	},
}

type ErrorDetector struct{}

func (d *ErrorDetector) Detect(r *models.Result) []Finding {
	if r == nil || r.Body500 == "" {
		return nil
	}

	var findings []Finding

	for _, rule := range errorRules {
		loc := rule.pattern.FindStringIndex(r.Body)
		if loc == nil {
			continue
		}

		findings = append(findings, Finding{
			Rule:        rule.name,
			Severity:    rule.severity,
			Evidence:    r.Body[loc[0]:loc[1]],
			Description: rule.description,
		})
	}

	return findings
}
