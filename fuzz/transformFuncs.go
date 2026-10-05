package fuzz

import (
	"fmt"
	"math/rand"
	"strings"
	"unicode/utf8"
)

type TransformFunc func([]string) []string

func ApplyTransforms(payloads []string, transforms ...TransformFunc) []string {
	for _, transform := range transforms {
		payloads = transform(payloads)
	}

	return payloads
}

func UrlEncode(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		var b strings.Builder

		for i := 0; i < len(payload); i++ {
			c := payload[i]

			if isUnreserved(c) {
				b.WriteByte(c)
				continue
			}

			fmt.Fprintf(&b, "%%%02X", c)
		}

		results = append(results, b.String())
	}

	return results
}

func DoubleUrlEncode(payloads []string) []string {
	return UrlEncode(UrlEncode(payloads))
}

func isUnreserved(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' ||
		c == '.' ||
		c == '_' ||
		c == '~'
}

func RandomCase(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		var b strings.Builder

		for _, r := range payload {
			if r >= 'a' && r <= 'z' {
				if rand.Intn(2) == 0 {
					r -= 'a' - 'A'
				}
			} else if r >= 'A' && r <= 'Z' {
				if rand.Intn(2) == 0 {
					r += 'a' - 'A'
				}
			}

			b.WriteRune(r)
		}

		results = append(results, b.String())
	}

	return results
}

func RandomWhitespace(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		var b strings.Builder

		for _, r := range payload {
			b.WriteRune(r)

			if r == ' ' || r == '\t' {
				switch rand.Intn(4) {
				case 0:
					b.WriteByte(' ')
				case 1:
					b.WriteByte('\t')
				case 2:
					b.WriteByte('\n')
				}
			}
		}

		results = append(results, b.String())
	}

	return results
}

func LowerCase(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		results = append(results, strings.ToLower(payload))
	}

	return results
}

func UpperCase(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		results = append(results, strings.ToUpper(payload))
	}

	return results
}

func UnicodeTricks(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		var b strings.Builder

		for _, r := range payload {
			if r > utf8.RuneSelf {
				b.WriteRune(r)
				continue
			}

			// Keep ASCII unchanged. This transformation is intended
			// to be extended with context-specific Unicode variants.
			b.WriteRune(r)
		}

		results = append(results, b.String())
	}

	return results
}

// PrefixSuffix adds a value before and after every payload.
//
// Example:
//
//	PrefixSuffix("safe", ".txt")("file")
//
//	=> "safefile.txt"
//
// This is useful for testing validation that only checks the beginning
// or end of a value while a later component interprets the entire value.
func PrefixSuffix(prefix, suffix string) TransformFunc {
	return func(payloads []string) []string {
		results := make([]string, 0, len(payloads))

		for _, payload := range payloads {
			results = append(results, prefix+payload+suffix)
		}

		return results
	}
}

// PrefixOnly adds a prefix to every payload.
func PrefixOnly(prefix string) TransformFunc {
	return func(payloads []string) []string {
		results := make([]string, 0, len(payloads))

		for _, payload := range payloads {
			results = append(results, prefix+payload)
		}

		return results
	}
}

// SuffixOnly adds a suffix to every payload.
func SuffixOnly(suffix string) TransformFunc {
	return func(payloads []string) []string {
		results := make([]string, 0, len(payloads))

		for _, payload := range payloads {
			results = append(results, payload+suffix)
		}

		return results
	}
}

// AddNullByte adds a literal NUL byte to the end of each payload.
func AddNullByte(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		results = append(results, payload+"\x00")
	}

	return results
}

// AddNullByteBefore adds a literal NUL byte before each payload.
func AddNullByteBefore(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		results = append(results, "\x00"+payload)
	}

	return results
}

// AddNullByteAround adds a literal NUL byte before and after each payload.
func AddNullByteAround(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		results = append(results, "\x00"+payload+"\x00")
	}

	return results
}

// AddEncodedNullByte adds a percent-encoded NUL representation.
func AddEncodedNullByte(payloads []string) []string {
	results := make([]string, 0, len(payloads))

	for _, payload := range payloads {
		results = append(results, payload+"%00")
	}

	return results
}
