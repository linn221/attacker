package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/linn221/attacker/fuzz"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/newjob", func(w http.ResponseWriter, r *http.Request) {
		job, err := jobFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := writeJobHeaders(job.Dir); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		go runJob(job, 1)
	})
	mux.HandleFunc("/resumejob", func(w http.ResponseWriter, r *http.Request) {
		job, err := jobFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		go runJob(job, job.Current)
	})
	mux.HandleFunc("/results", func(w http.ResponseWriter, r *http.Request) {
		dir, err := dirFromQuery(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f, err := os.Open(filepath.Join(dir, "processed", "results.csv"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"results.csv\"")
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("stream results: %v", err)
		}
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		dir, err := dirFromQuery(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		status, err := jobStatus(dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})
	log.Fatal(http.ListenAndServe(":6423", mux))
}

type Job struct {
	Dir     string
	GapMin  int
	GapMax  int
	Current int
	End     int
	meta    jobMeta
}

type jobMeta struct {
	Current int    `json:"current"`
	End     int    `json:"end"`
	Gap     string `json:"gap"`
}

type jobStatusBody struct {
	Processed int `json:"processed"`
	Left      int `json:"left"`
	Errors    int `json:"errors"`
}

func (j *Job) processTask(id int) (int, error) { // nextId, error
	if id > j.End {
		return 0, nil
	}

	if err := j.executeTask(id); err != nil {
		if werr := j.appendError(id, err); werr != nil {
			return 0, werr
		}
	}
	return j.finishTask(id)
}

func (j *Job) executeTask(id int) error {
	src := filepath.Join(j.Dir, fmt.Sprintf("%d.json", id))
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %d.json: %w", id, err)
	}

	var shot fuzz.Shot
	if err := json.Unmarshal(data, &shot); err != nil {
		return fmt.Errorf("unmarshal %d.json: %w", id, err)
	}

	req := shot.ToRequest()
	req.SetDefault()
	fmt.Printf("%s %s\n", req.Method, req.URL)

	client := &fuzz.Client{HTTPClient: &http.Client{}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %d: %w", id, err)
	}

	processed := filepath.Join(j.Dir, "processed")
	if err := os.MkdirAll(processed, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(processed, resp.Id), resp.Body, 0600); err != nil {
		return err
	}
	var headerBuf bytes.Buffer
	if err := resp.Headers.Write(&headerBuf); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(processed, resp.Id+".headers"), headerBuf.Bytes(), 0600); err != nil {
		return err
	}
	if err := os.Rename(src, filepath.Join(processed, fmt.Sprintf("%d.json", id))); err != nil {
		return err
	}

	results, err := os.OpenFile(filepath.Join(processed, "results.csv"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := fmt.Fprintln(results, resp.String())
	closeErr := results.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (j *Job) finishTask(id int) (int, error) {
	j.Current = id + 1
	j.meta.Current = j.Current
	if err := writeMeta(j.Dir, j.meta); err != nil {
		return 0, err
	}
	if id >= j.End {
		return 0, nil
	}
	span := j.GapMax - j.GapMin
	secs := j.GapMin
	if span > 0 {
		secs += rand.Intn(span + 1)
	}
	time.Sleep(time.Duration(secs) * time.Second)
	return id + 1, nil
}

func (j *Job) appendError(id int, taskErr error) error {
	processed := filepath.Join(j.Dir, "processed")
	if err := os.MkdirAll(processed, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(processed, "errors.csv"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{strconv.Itoa(id), taskErr.Error()}); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func NewJob(dir string) *Job {
	if _, err := os.ReadDir(dir); err != nil {
		log.Printf("read job dir: %v", err)
		return nil
	}
	meta, err := readMeta(dir)
	if err != nil {
		log.Printf("read meta.json: %v", err)
		return nil
	}
	gapMin, gapMax, err := parseGap(meta.Gap)
	if err != nil {
		log.Printf("read gap: %v", err)
		return nil
	}
	if meta.Current < 1 {
		meta.Current = 1
	}
	return &Job{
		Dir:     dir,
		GapMin:  gapMin,
		GapMax:  gapMax,
		Current: meta.Current,
		End:     meta.End,
		meta:    meta,
	}
}

func runJob(job *Job, id int) {
	defer printStatusCounts(job.Dir)
	if id < 1 {
		id = 1
	}
	for id > 0 {
		next, err := job.processTask(id)
		if err != nil {
			log.Printf("task %d: %v", id, err)
			return
		}
		id = next
	}
}

func jobFromRequest(r *http.Request) (*Job, error) {
	dir, err := dirFromQuery(r)
	if err != nil {
		return nil, err
	}
	job := NewJob(dir)
	if job == nil {
		return nil, fmt.Errorf("invalid job directory")
	}
	return job, nil
}

func dirFromQuery(r *http.Request) (string, error) {
	dir := strings.TrimSpace(r.URL.Query().Get("dir"))
	if dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	return dir, nil
}

func writeJobHeaders(dir string) error {
	processed := filepath.Join(dir, "processed")
	if err := os.MkdirAll(processed, 0700); err != nil {
		return err
	}
	if err := writeCSVHeader(filepath.Join(processed, "results.csv"), []string{"id", "url", "status_code", "body_hash", "content_type", "body_500"}); err != nil {
		return err
	}
	return writeCSVHeader(filepath.Join(processed, "errors.csv"), []string{"id", "error"})
}

func writeCSVHeader(path string, header []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func jobStatus(dir string) (jobStatusBody, error) {
	if _, err := os.ReadDir(dir); err != nil {
		return jobStatusBody{}, fmt.Errorf("invalid job directory")
	}
	meta, err := readMeta(dir)
	if err != nil {
		return jobStatusBody{}, fmt.Errorf("read meta.json: %w", err)
	}
	processed, err := countCSVDataRows(filepath.Join(dir, "processed", "results.csv"))
	if err != nil {
		return jobStatusBody{}, err
	}
	errs, err := countCSVDataRows(filepath.Join(dir, "processed", "errors.csv"))
	if err != nil {
		return jobStatusBody{}, err
	}
	left := meta.End - processed - errs
	if left < 0 {
		left = 0
	}
	return jobStatusBody{Processed: processed, Left: left, Errors: errs}, nil
}

func printStatusCounts(dir string) {
	f, err := os.Open(filepath.Join(dir, "processed", "results.csv"))
	if err != nil {
		log.Printf("results.csv: %v", err)
		return
	}
	defer f.Close()

	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		log.Printf("results.csv: %v", err)
		return
	}
	col := -1
	for i, name := range header {
		if name == "status_code" {
			col = i
			break
		}
	}
	if col < 0 {
		log.Printf("results.csv: status_code column missing")
		return
	}

	counts := map[string]int{}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("results.csv: %v", err)
			return
		}
		if col >= len(row) || row[col] == "" {
			continue
		}
		counts[row[col]]++
	}

	codes := make([]string, 0, len(counts))
	for code := range counts {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool {
		ai, erri := strconv.Atoi(codes[i])
		aj, errj := strconv.Atoi(codes[j])
		if erri != nil || errj != nil {
			return codes[i] < codes[j]
		}
		return ai < aj
	})
	for _, code := range codes {
		fmt.Printf("%s %d\n", code, counts[code])
	}
}

func countCSVDataRows(path string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	n := 0
	for {
		if _, err := r.Read(); err == io.EOF {
			break
		} else if err != nil {
			return 0, err
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n - 1, nil
}

func readMeta(dir string) (jobMeta, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return jobMeta{}, err
	}
	var meta jobMeta
	if err := json.Unmarshal(b, &meta); err != nil {
		return jobMeta{}, err
	}
	return meta, nil
}

func writeMeta(dir string, meta jobMeta) error {
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(dir, "meta.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseGap(gap string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(gap), ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("gap must be min:max")
	}
	min, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("gap min: %w", err)
	}
	max, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("gap max: %w", err)
	}
	if min < 0 || max < 0 || min > max {
		return 0, 0, fmt.Errorf("gap must be min:max with 0 <= min <= max")
	}
	return min, max, nil
}
