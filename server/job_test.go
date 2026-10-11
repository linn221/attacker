package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestNewJobReturnsResultsURLAndListsTitle(t *testing.T) {
	root := t.TempDir()
	restoreDB := useTestDB(t, filepath.Join(root, "test.db"))
	defer restoreDB()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	const (
		jobDir = "./jobs/basic-http-probe-test"
		title  = "Basic Http Probe"
	)
	if err := os.MkdirAll(jobDir, 0700); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if job, err := jobByName(jobDir); err == nil {
			stopJobRun(job.Id)
		}
	}()

	q := url.Values{}
	q.Set("dir", jobDir)
	q.Set("title", title)
	q.Set("end", "1")
	q.Set("gap", "0:0")
	req := httptest.NewRequest(http.MethodGet, "/newjob?"+q.Encode(), nil)
	req.Host = "127.0.0.1:6423"
	rec := httptest.NewRecorder()
	handleNewJob(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("newjob %d: %s", rec.Code, rec.Body.String())
	}
	wantURL := "http://127.0.0.1:6423/results?dir=.%2Fjobs%2Fbasic-http-probe-test"
	if strings.TrimSpace(rec.Body.String()) != wantURL {
		t.Fatalf("url %q", rec.Body.String())
	}

	index := httptest.NewRecorder()
	handleIndex(index, httptest.NewRequest(http.MethodGet, "/", nil))
	body := index.Body.String()
	if !strings.Contains(body, title) || !strings.Contains(body, jobDir) {
		t.Fatalf("index missing title or directory: %s", body)
	}

	results := httptest.NewRecorder()
	handleResults(results, httptest.NewRequest(http.MethodGet, "/results?"+url.Values{"dir": {jobDir}}.Encode(), nil))
	page := results.Body.String()
	if results.Code != http.StatusOK || !strings.Contains(page, title) || !strings.Contains(page, jobDir) {
		t.Fatalf("results %d missing title or directory: %s", results.Code, page)
	}
}

func useTestDB(t *testing.T, path string) func() {
	t.Helper()
	previous := db
	if err := initDB(func() (*gorm.DB, error) {
		return gorm.Open(sqlite.Open(path), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
	}); err != nil {
		t.Fatal(err)
	}
	return func() { db = previous }
}

func TestNewJobRequiresTitle(t *testing.T) {
	root := t.TempDir()
	restoreDB := useTestDB(t, filepath.Join(root, "test.db"))
	defer restoreDB()

	dir := filepath.Join(root, "job")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("dir", dir)
	q.Set("end", "1")
	q.Set("gap", "0:0")
	rec := httptest.NewRecorder()
	handleNewJob(rec, httptest.NewRequest(http.MethodGet, "/newjob?"+q.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("status %d: %s", rec.Code, body)
	}
}
