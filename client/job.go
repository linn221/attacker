package client

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/linn221/attacker/fuzz"
	"github.com/linn221/attacker/models"
)

// NewJob builds the shots, stores them under jobs/ in the working directory, and starts the job.
// title is the label stored with the job. sleep is the min:max pause, in seconds, between requests.
// The results URL returned by the server is printed.
func NewJob(backendUrl string, title string, sleep string, f func(fz *fuzz.Fuzz)) {
	title = strings.TrimSpace(title)
	if title == "" {
		log.Fatal("title is required")
	}
	base := models.Shot{
		Https:   true,
		Queries: make(map[string][]string),
		Headers: make(map[string][]string),
		Cookies: make(map[string][]string),
	}
	fuzzer := fuzz.NewFuzzer(&base)
	f(fuzzer)
	shots := fuzzer.Fuzz()

	dir, err := jobDirectory(title)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal(err)
	}
	// Finish every file before /newjob. The server reads 1.json immediately,
	// and returning from main kills any writer still inside WriteFile.
	if err := writeShots(dir, shots); err != nil {
		log.Fatal(err)
	}

	u, err := url.Parse(backendUrl + "/newjob")
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	q.Set("dir", dir)
	q.Set("title", title)
	q.Set("end", fmt.Sprint(len(shots)))
	q.Set("gap", sleep)
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	msg, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("newjob: %s: %s", resp.Status, msg)
	}
	fmt.Println(strings.TrimSpace(string(msg)))
}

// jobDirectory builds a new path under jobs/ in the current working directory.
// The last element is a safe form of title plus a random id, so two jobs can share a title. It does not create the directory.
func jobDirectory(title string) (string, error) {
	id, err := randomUUID()
	if err != nil {
		return "", err
	}
	return "./jobs/" + slugTitle(title) + "-" + id, nil
}

// slugTitle turns title into one safe path element.
// Letters and digits are kept, in lower case. Every other run of characters becomes a single hyphen. An empty result is "job".
func slugTitle(title string) string {
	var b strings.Builder
	prevHyphen := false
	for _, r := range strings.ToLower(strings.TrimSpace(title)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevHyphen = false
			continue
		}
		if !prevHyphen && b.Len() > 0 {
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	s := strings.Trim(b.String(), "-")
	const maxSlug = 80
	if len(s) > maxSlug {
		s = strings.Trim(s[:maxSlug], "-")
	}
	if s == "" {
		return "job"
	}
	return s
}

// randomUUID returns a random UUID.
// It returns an error when the system random source fails.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// writeShots writes one complete JSON file per shot, numbered from 1.
// Writes run a few at a time. A file appears only after its bytes are on disk,
// so a reader never sees a truncated or empty shot.
func writeShots(dir string, shots []models.Shot) error {
	const workers = 32
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error

	for i := range shots {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := writeShotFile(dir, i+1, shots[i]); err != nil {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return first
}

func writeShotFile(dir string, n int, shot models.Shot) error {
	data, err := json.Marshal(shot)
	if err != nil {
		return fmt.Errorf("shot %d: %w", n, err)
	}
	final := filepath.Join(dir, fmt.Sprintf("%d.json", n))
	tmp, err := os.CreateTemp(dir, ".shot-*.tmp")
	if err != nil {
		return fmt.Errorf("shot %d: %w", n, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("shot %d: %w", n, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("shot %d: %w", n, err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("shot %d: %w", n, err)
	}
	return nil
}
