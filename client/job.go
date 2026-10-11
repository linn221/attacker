package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/linn221/attacker/fuzz"
	"github.com/linn221/attacker/models"
)

func NewJob(backendUrl string, dir string, sleep string, f func(fz *fuzz.Fuzz)) {
	base := models.Shot{
		Https:   true,
		Queries: make(map[string][]string),
		Headers: make(map[string]string),
		Cookies: make(map[string][]string),
	}
	fuzzer := fuzz.NewFuzzer(&base)
	f(fuzzer)
	shots := fuzzer.Fuzz()

	err := os.MkdirAll(dir, 0700)
	if err != nil {
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
	q.Set("end", fmt.Sprint(len(shots)))
	q.Set("gap", sleep)
	u.RawQuery = q.Encode()
	resp, err := http.Get(u.String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		log.Fatalf("newjob: %s: %s", resp.Status, msg)
	}
	fmt.Println(backendUrl + "/results?dir=" + dir)
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
