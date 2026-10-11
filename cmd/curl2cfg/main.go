// Command curl2cfg reads shell text, skips commands that are not curl, and
// writes a YAML list of configurations. Load that file with fuzz.LoadConfigurations.
//
//	go run ./cmd/curl2cfg -o requests.yml [file...]
//
// With no -o, the YAML is written to stdout. With no files, curl2cfg reads stdin.
// "-" also reads stdin.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/linn221/attacker/fuzz"
)

func main() {
	outPath := flag.String("o", "", "write the configuration list to this .yml file instead of stdout")
	flag.Parse()

	text, err := readInput(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "curl2cfg:", err)
		os.Exit(1)
	}
	cfgs, errs := fuzz.ParseCurlCommands(text)
	for _, err := range errs {
		fmt.Fprintln(os.Stderr, "curl2cfg:", err)
	}
	data, err := fuzz.MarshalConfigurations(cfgs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "curl2cfg:", err)
		os.Exit(1)
	}
	if *outPath != "" {
		err = os.WriteFile(*outPath, data, 0o600)
	} else {
		_, err = os.Stdout.Write(data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "curl2cfg:", err)
		os.Exit(1)
	}
	if len(errs) > 0 {
		os.Exit(1)
	}
	if strings.TrimSpace(text) != "" && len(cfgs) == 0 {
		fmt.Fprintln(os.Stderr, "curl2cfg: no curl commands found")
		os.Exit(1)
	}
}

func readInput(args []string) (string, error) {
	if len(args) == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	var b strings.Builder
	for _, arg := range args {
		var data []byte
		var err error
		if arg == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(arg)
		}
		if err != nil {
			return "", err
		}
		b.Write(data)
		if len(data) == 0 || data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
