package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/linn221/attacker/fuzz"
	"github.com/linn221/attacker/models"
)

// main opens the database and serves the jobs page, job controls, and results pages on port 6423.
func main() {
	if err := initDB(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/newjob", func(w http.ResponseWriter, r *http.Request) {
		if dir, err := dirFromQuery(r); err == nil {
			if existing, err := jobByName(dir); err == nil {
				stopJobRun(existing.Id)
			}
		}
		job, err := jobFromRequest(r, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !startJob(job, 1) {
			http.Error(w, "job is already running", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/resumejob", handleResumeJob)
	mux.HandleFunc("/stopjob", handleStopJob)
	mux.HandleFunc("/results", handleResults)
	mux.HandleFunc("/results/table", handleResultsTable)
	mux.HandleFunc("/results/detail", handleResultDetail)
	mux.HandleFunc("/results/file", handleResultFile)
	mux.HandleFunc("/results/status", handleResultStatus)
	mux.HandleFunc("/results/hide", handleResultHide)
	mux.HandleFunc("/results/pin", handleResultPin)
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
	JobID   int
	GapMin  int
	GapMax  int
	Current int
	End     int
}

type jobStatusBody struct {
	Processed int `json:"processed"`
	Left      int `json:"left"`
	Errors    int `json:"errors"`
}

// processTask runs task id, then moves the job forward.
// A failed request is logged and still counts as finished. A cancelled ctx skips the pause and stops the loop.
// It returns the next task id, or 0 when id is past the end or the job was stopped.
// It returns an error only when the new current task cannot be saved.
func (j *Job) processTask(ctx context.Context, id int) (int, error) {
	if id > j.End {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 0, nil
	}

	if err := j.executeTask(ctx, id); err != nil {
		log.Printf("task %d: %v", id, err)
	}
	return j.finishTask(ctx, id)
}

// executeTask sends the shot stored in id.json and saves the response.
// The body and headers are written under processed/, named by id, and a result row is inserted.
// It returns an error if the shot cannot be read or the response cannot be stored.
func (j *Job) executeTask(ctx context.Context, id int) error {
	src := filepath.Join(j.Dir, fmt.Sprintf("%d.json", id))
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %d.json: %w", id, err)
	}

	var shot models.Shot
	if err := json.Unmarshal(data, &shot); err != nil {
		return fmt.Errorf("unmarshal %d.json: %w", id, err)
	}

	req, err := shot.ToRequest()
	if err != nil {
		return fmt.Errorf("request %d: %w", id, err)
	}
	fmt.Printf("%s %s\n", req.Method, req.URL)

	client := &fuzz.Client{HTTPClient: &http.Client{}, Context: ctx}
	then := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %d: %w", id, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("request %d: %w", id, err)
	}
	latency := time.Since(then)

	taskID := strconv.Itoa(id)
	processed := filepath.Join(j.Dir, "processed")
	if err := os.MkdirAll(processed, 0700); err != nil {
		return err
	}
	responseFile := filepath.Join(processed, taskID)
	responseHeaders := filepath.Join(processed, taskID+".headers")
	if err := os.WriteFile(responseFile, body, 0600); err != nil {
		return err
	}
	var headerBuf bytes.Buffer
	if err := resp.Header.Write(&headerBuf); err != nil {
		return err
	}
	if err := os.WriteFile(responseHeaders, headerBuf.Bytes(), 0600); err != nil {
		return err
	}
	if err := os.Rename(src, filepath.Join(processed, fmt.Sprintf("%d.json", id))); err != nil {
		return err
	}
	return insertResult(j.JobID, id, shot, req, resp, body, latency, responseFile, responseHeaders)
}

// finishTask saves id+1 as the next task, then waits for a random pause inside the job's gap.
// A cancelled ctx saves that next id and returns 0 without waiting. It returns 0 when id is the last task.
// It returns an error if current cannot be saved.
func (j *Job) finishTask(ctx context.Context, id int) (int, error) {
	j.Current = id + 1
	if err := updateJobCurrent(j.JobID, j.Current); err != nil {
		return 0, err
	}
	if id >= j.End || ctx.Err() != nil {
		return 0, nil
	}
	span := j.GapMax - j.GapMin
	secs := j.GapMin
	if span > 0 {
		secs += rand.Intn(span + 1)
	}
	timer := time.NewTimer(time.Duration(secs) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, nil
	case <-timer.C:
		return id + 1, nil
	}
}

type jobRun struct {
	cancel context.CancelFunc
	done   chan struct{}
}

var (
	jobsMu      sync.Mutex
	jobsRunning = map[int]*jobRun{}
)

// beginJob records id as running and returns the context Stop cancels.
// It returns false when that job is already running.
func beginJob(id int) (context.Context, bool) {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	if _, ok := jobsRunning[id]; ok {
		return nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	jobsRunning[id] = &jobRun{cancel: cancel, done: make(chan struct{})}
	return ctx, true
}

// endJob forgets id and closes its done channel.
// It does nothing when id is not the active run.
func endJob(id int) {
	jobsMu.Lock()
	run := jobsRunning[id]
	delete(jobsRunning, id)
	jobsMu.Unlock()
	if run != nil {
		close(run.done)
	}
}

// jobIsRunning reports whether id has an active runner.
func jobIsRunning(id int) bool {
	jobsMu.Lock()
	_, ok := jobsRunning[id]
	jobsMu.Unlock()
	return ok
}

// stopJobRun cancels the runner for id and waits until that runner has exited.
// It returns immediately when id is not running. The wait includes a request already in flight, which is cancelled with the runner.
func stopJobRun(id int) {
	jobsMu.Lock()
	run := jobsRunning[id]
	jobsMu.Unlock()
	if run == nil {
		return
	}
	run.cancel()
	<-run.done
}

// startJob runs tasks from id through job.End in the background.
// An id below 1 starts at task 1. It returns false when the job is already running or id is past the end.
func startJob(job *Job, id int) bool {
	if id < 1 {
		id = 1
	}
	if id > job.End {
		return false
	}
	ctx, ok := beginJob(job.JobID)
	if !ok {
		return false
	}
	if err := updateJobStatus(job.JobID, jobStatusProcessing); err != nil {
		endJob(job.JobID)
		log.Printf("job %d: %v", job.JobID, err)
		return false
	}
	go func() {
		defer func() {
			status := jobStatusStopped
			if job.Current > job.End {
				status = jobStatusCompleted
			}
			if err := updateJobStatus(job.JobID, status); err != nil {
				log.Printf("job %d: %v", job.JobID, err)
			}
			endJob(job.JobID)
		}()
		for id > 0 {
			if ctx.Err() != nil {
				return
			}
			next, err := job.processTask(ctx, id)
			if err != nil {
				log.Printf("task %d: %v", id, err)
				return
			}
			id = next
		}
	}()
	return true
}

// handleResumeJob starts the job named by dir at its saved task.
// A finished job is rejected. A job that is already running is left as it is.
// It writes an empty 200 body and asks the status card to refresh.
func handleResumeJob(w http.ResponseWriter, r *http.Request) {
	job, err := jobFromRequest(r, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if job.Current > job.End {
		http.Error(w, "job is complete", http.StatusConflict)
		return
	}
	startJob(job, job.Current)
	w.Header().Set("HX-Trigger", "job-status")
	w.WriteHeader(http.StatusOK)
}

// handleStopJob cancels the runner for the job named by dir.
// Stopping a job that is not running still returns 200. It asks the status card to refresh.
func handleStopJob(w http.ResponseWriter, r *http.Request) {
	dir, err := dirFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	job, err := jobByName(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stopJobRun(job.Id)
	w.Header().Set("HX-Trigger", "job-status")
	w.WriteHeader(http.StatusOK)
}

// jobFromRequest builds the runner for the dir query parameter.
// When create is true, end and gap are read from the query and the job is inserted or reset. Otherwise the existing job is loaded.
// It returns that runner, or an error when the directory or the job is invalid.
func jobFromRequest(r *http.Request, create bool) (*Job, error) {
	dir, err := dirFromQuery(r)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("invalid job directory")
	}
	var model JobModel
	if create {
		end, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("end")))
		if err != nil || end < 1 {
			return nil, fmt.Errorf("end is required")
		}
		gap := strings.TrimSpace(r.URL.Query().Get("gap"))
		if _, _, err := parseGap(gap); err != nil {
			return nil, err
		}
		model, err = createJob(dir, gap, end)
		if err != nil {
			return nil, err
		}
	} else {
		model, err = jobByName(dir)
		if err != nil {
			return nil, err
		}
	}
	return jobFromModel(dir, model)
}

// jobFromModel turns a stored job into the runner used for a directory.
// dir is that job's directory. It returns an error when model.Gap is not min:max.
func jobFromModel(dir string, model JobModel) (*Job, error) {
	gapMin, gapMax, err := parseGap(model.Gap)
	if err != nil {
		return nil, err
	}
	current := model.Current
	if current < 1 {
		current = 1
	}
	return &Job{
		Dir:     dir,
		JobID:   model.Id,
		GapMin:  gapMin,
		GapMax:  gapMax,
		Current: current,
		End:     model.End,
	}, nil
}

// dirFromQuery reads the dir query parameter.
// It returns an error when dir is missing.
func dirFromQuery(r *http.Request) (string, error) {
	dir := strings.TrimSpace(r.URL.Query().Get("dir"))
	if dir == "" {
		return "", fmt.Errorf("dir is required")
	}
	return dir, nil
}

// jobStatus reports progress for the job whose name is dir.
// Processed is the number of stored results. Errors are finished tasks with no result. Left is the tasks not started yet.
// It returns that summary, or an error when the job cannot be loaded.
func jobStatus(dir string) (jobStatusBody, error) {
	job, err := jobByName(dir)
	if err != nil {
		return jobStatusBody{}, err
	}
	processed, err := countResults(job.Id)
	if err != nil {
		return jobStatusBody{}, err
	}
	done := job.Current - 1
	if done < 0 {
		done = 0
	}
	if done > job.End {
		done = job.End
	}
	errs := done - processed
	if errs < 0 {
		errs = 0
	}
	left := job.End - done
	if left < 0 {
		left = 0
	}
	return jobStatusBody{Processed: processed, Left: left, Errors: errs}, nil
}

// parseGap splits a min:max pause into its two second counts.
// It returns an error unless both numbers exist and 0 <= min <= max.
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
