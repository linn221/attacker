package client

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSlugTitle(t *testing.T) {
	if got := slugTitle("Basic Http Probe"); got != "basic-http-probe" {
		t.Fatalf("slug %q", got)
	}
	if got := slugTitle("../etc/passwd"); got != "etc-passwd" {
		t.Fatalf("slug %q", got)
	}
	if got := slugTitle("!!!"); got != "job" {
		t.Fatalf("slug %q", got)
	}
}

func TestJobDirectoryFromTitle(t *testing.T) {
	dir, err := jobDirectory("Basic Http Probe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, "./jobs/basic-http-probe-") {
		t.Fatalf("dir %q", dir)
	}
	base := filepath.Base(dir)
	if strings.Contains(base, "/") || strings.Contains(base, "..") {
		t.Fatalf("base %q", base)
	}
	other, err := jobDirectory("Basic Http Probe")
	if err != nil {
		t.Fatal(err)
	}
	if other == dir {
		t.Fatal("expected a unique directory")
	}
}
