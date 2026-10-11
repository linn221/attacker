package main

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// handleIndex writes the page that lists every job.
// Each job links to its results page. Any path other than / is a 404, because / is the fallback route.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	jobs, err := loadIndexJobs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, renderIndexPage(jobs))
}

type indexJob struct {
	Title     string
	Path      string
	Status    string
	Processed int
	Left      int
	Errors    int
	Gap       string
	Href      string
}

// loadIndexJobs reads every job and the counts shown on the index.
// It returns those rows newest first, or an error when the jobs or their result counts cannot be loaded.
func loadIndexJobs() ([]indexJob, error) {
	jobs, err := listJobs()
	if err != nil {
		return nil, err
	}
	out := make([]indexJob, 0, len(jobs))
	for _, job := range jobs {
		processed, err := countResults(job.Id)
		if err != nil {
			return nil, err
		}
		left, errs := jobProgress(job, processed)
		q := url.Values{}
		q.Set("dir", job.Name)
		out = append(out, indexJob{
			Title:     jobTitle(job.Name),
			Path:      job.Name,
			Status:    displayJobStatus(job.CurrentStatus, left),
			Processed: processed,
			Left:      left,
			Errors:    errs,
			Gap:       jobGapText(job.Gap),
			Href:      "/results?" + q.Encode(),
		})
	}
	return out, nil
}

// jobTitle returns the directory's base name for the job list.
// A name that is already a single path element is returned unchanged.
func jobTitle(name string) string {
	base := filepath.Base(name)
	if base == "." || base == string(filepath.Separator) || base == name {
		return name
	}
	return base
}

// jobGapText renders a stored min:max gap the same way the status card does.
// An unparsable gap is returned unchanged.
func jobGapText(gap string) string {
	min, max, err := parseGap(gap)
	if err != nil {
		return gap
	}
	return formatGap(min, max)
}

// jobProgress counts tasks not started yet and finished tasks that stored no result.
// processed is the number of result rows. It returns left and errors.
func jobProgress(job JobModel, processed int) (int, int) {
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
	return left, errs
}

// renderIndexPage builds the document that lists jobs.
// It returns that HTML. An empty jobs list says that no jobs are stored.
func renderIndexPage(jobs []indexJob) string {
	var body strings.Builder
	body.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	body.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	body.WriteString(`<title>Jobs</title>`)
	body.WriteString(`<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">`)
	body.WriteString(`</head><body class="bg-light">`)
	body.WriteString(`<div class="container py-4" style="max-width:900px">`)
	body.WriteString(`<h1 class="h4 mb-3">Jobs</h1>`)
	if len(jobs) == 0 {
		body.WriteString(`<div class="card shadow-sm"><div class="card-body text-secondary">No jobs yet.</div></div>`)
	} else {
		body.WriteString(`<div class="list-group shadow-sm">`)
		for _, job := range jobs {
			body.WriteString(renderIndexJob(job))
		}
		body.WriteString(`</div>`)
	}
	body.WriteString(`</div></body></html>`)
	return body.String()
}

// renderIndexJob builds one job link.
// The whole row opens that job's results page. It returns the anchor HTML.
func renderIndexJob(job indexJob) string {
	var b strings.Builder
	b.WriteString(`<a class="list-group-item list-group-item-action p-3" href="` + html.EscapeString(job.Href) + `">`)
	b.WriteString(`<div class="d-flex flex-wrap justify-content-between gap-2 align-items-start">`)
	b.WriteString(`<div class="me-auto">`)
	b.WriteString(`<div class="fw-semibold text-break">` + html.EscapeString(job.Title) + `</div>`)
	if job.Path != job.Title {
		b.WriteString(`<div class="small text-secondary text-break">` + html.EscapeString(job.Path) + `</div>`)
	}
	b.WriteString(`</div>`)
	b.WriteString(jobStateBadge(job.Status))
	b.WriteString(`</div>`)
	b.WriteString(`<div class="d-flex flex-wrap gap-3 small mt-2">`)
	b.WriteString(indexStat("Processed", strconv.Itoa(job.Processed)))
	b.WriteString(indexStat("Left", strconv.Itoa(job.Left)))
	b.WriteString(indexStat("Errors", strconv.Itoa(job.Errors)))
	b.WriteString(indexStat("Gap", job.Gap))
	b.WriteString(`</div></a>`)
	return b.String()
}

// indexStat builds one labeled value inside a job row.
// It returns the span HTML.
func indexStat(label, value string) string {
	return `<span><span class="text-secondary me-1">` + html.EscapeString(label) + `</span><span class="fw-semibold">` + html.EscapeString(value) + `</span></span>`
}
