package main

import (
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/linn221/attacker/models"
)

// handleResults writes the HTML results page for the job named by the dir query parameter.
func handleResults(w http.ResponseWriter, r *http.Request) {
	page, status, err := loadResultPage(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, renderResultsPage(r, page))
}

// handleResultsTable writes the results table for the current filters.
// The query is the same as /results. It returns the table block the Refresh button swaps in.
func handleResultsTable(w http.ResponseWriter, r *http.Request) {
	page, status, err := loadResultPage(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, renderResultsTable(r.URL.Query(), page))
}

// loadResultPage loads the filtered results for the dir on r.
// It returns the page, the HTTP status for a failure, and that error.
func loadResultPage(r *http.Request) (resultPage, int, error) {
	dir, err := dirFromQuery(r)
	if err != nil {
		return resultPage{}, http.StatusBadRequest, err
	}
	job, err := jobByName(dir)
	if err != nil {
		return resultPage{}, http.StatusNotFound, err
	}
	page, err := queryResults(job.Id, strings.TrimSpace(r.URL.Query().Get("search")), strings.TrimSpace(r.URL.Query().Get("status_code")), r.URL.Query().Get("raw"), r.URL.Query()["exclude_hash"], parseSorts(r.URL.Query()))
	if err != nil {
		page.queryError = err.Error()
	}
	page.title = job.Title
	return page, http.StatusOK, nil
}

// handleResultDetail writes the HTML fragment htmx places under one result row.
// The query needs dir, id, and part. part selects full_url, queries, request_body, request_headers, response_headers, or response_body.
func handleResultDetail(w http.ResponseWriter, r *http.Request) {
	dir, err := dirFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil || id < 1 {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	job, err := jobByName(dir)
	if err != nil {
		io.WriteString(w, renderDetailFragment("Error", err.Error(), true))
		return
	}
	row, err := resultViewByID(id)
	if err != nil || row.JobId != job.Id {
		io.WriteString(w, renderDetailFragment("Error", "result not found", true))
		return
	}
	title, text, failed := detailContent(row, r.URL.Query().Get("part"))
	io.WriteString(w, renderDetailFragment(title, text, failed))
}

// handleResultFile serves one stored file for a result so the browser can open it.
// kind=response serves the response body file. kind=shot serves processed/<index>.json.
func handleResultFile(w http.ResponseWriter, r *http.Request) {
	dir, err := dirFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil || id < 1 {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	job, err := jobByName(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	row, err := resultViewByID(id)
	if err != nil || row.JobId != job.Id {
		http.Error(w, "result not found", http.StatusNotFound)
		return
	}
	path, contentType, err := resultFile(dir, row, r.URL.Query().Get("kind"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	serveResultFile(w, r, path, contentType)
}

// handleResultStatus writes the job status card that the results page polls.
// The query needs dir. It returns that card as an HTML fragment.
func handleResultStatus(w http.ResponseWriter, r *http.Request) {
	dir, err := dirFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, renderJobStatus(dir))
}

// handleResultHide checks that id belongs to the job named by dir, then writes an empty body.
// The results table swaps that response over the result row, which removes the row from view.
func handleResultHide(w http.ResponseWriter, r *http.Request) {
	dir, err := dirFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil || id < 1 {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	job, err := jobByName(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	row, err := resultViewByID(id)
	if err != nil || row.JobId != job.Id {
		http.Error(w, "result not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleResultPin sets IsPin on the result id for the job named by dir.
// pin=0 clears the pin. Any other value sets it. It asks the results table to refresh and returns an empty body.
func handleResultPin(w http.ResponseWriter, r *http.Request) {
	dir, err := dirFromQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("id")))
	if err != nil || id < 1 {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	job, err := jobByName(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	row, err := resultViewByID(id)
	if err != nil || row.JobId != job.Id {
		http.Error(w, "result not found", http.StatusNotFound)
		return
	}
	if err := setResultPinned(row.Id, r.URL.Query().Get("pin") != "0"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("HX-Trigger", "results-refresh")
	w.WriteHeader(http.StatusOK)
}

type resultPage struct {
	rows       []models.Result
	all        int
	c200       int
	c300       int
	c400       int
	c500       int
	where      string
	queryError string
	title      string
}

// renderResultsPage builds the full results document from page and the filters on r.
// It returns that HTML.
func renderResultsPage(r *http.Request, page resultPage) string {
	q := r.URL.Query()

	var body strings.Builder
	body.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	body.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	heading := strings.TrimSpace(page.title)
	if heading == "" {
		heading = "Results"
	}
	body.WriteString(`<title>` + html.EscapeString(heading) + `</title>`)
	body.WriteString(`<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">`)
	body.WriteString(`<script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js"></script>`)
	body.WriteString(`<style>`)
	body.WriteString(`.detail-pre{max-height:24rem;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:.8125rem;}`)
	body.WriteString(`tr.detail:not(:has(.detail-body)){display:none;}`)
	body.WriteString(`td.body500{max-width:22rem;}td.body500 div{max-height:4.5rem;overflow:auto;white-space:pre-wrap;}`)
	body.WriteString(`.hide-col{width:1%;}.hide-col .btn{--bs-btn-padding-y:0;--bs-btn-padding-x:.28rem;--bs-btn-font-size:.7rem;line-height:1.1;}`)
	body.WriteString(`.table tbody tr.pinned > td{background-color:#fff4c2;}.table-hover tbody tr.pinned:hover > td{background-color:#ffe89a;}`)
	body.WriteString(`</style></head><body class="bg-light">`)
	body.WriteString(`<div class="container-fluid py-4" style="max-width:1400px">`)
	body.WriteString(`<div class="d-flex flex-wrap align-items-baseline gap-3 mb-1">`)
	body.WriteString(`<h1 class="h4 mb-0">` + html.EscapeString(heading) + `</h1>`)
	body.WriteString(`<a href="/">All jobs</a>`)
	body.WriteString(`</div>`)
	body.WriteString(`<p class="text-secondary small text-break mb-3">` + html.EscapeString(q.Get("dir")) + `</p>`)
	body.WriteString(renderJobStatus(q.Get("dir")))
	body.WriteString(renderFilters(q))
	body.WriteString(renderRawQuery(q, page.where))
	if page.queryError != "" {
		body.WriteString(`<div class="alert alert-warning">` + html.EscapeString(page.queryError) + `</div>`)
	}
	body.WriteString(renderSortForm(q))
	body.WriteString(renderExcluded(q))
	body.WriteString(renderResultsTable(q, page))
	body.WriteString(`</div></body></html>`)
	return body.String()
}

// renderFilters builds the search and status form.
// Hidden fields keep dir, every exclude_hash value, and the current sorts from q. It returns the form HTML.
func renderFilters(q url.Values) string {
	var hidden strings.Builder
	hidden.WriteString(hiddenValue("dir", q.Get("dir")))
	for _, hash := range q["exclude_hash"] {
		if hash == "" {
			continue
		}
		hidden.WriteString(hiddenValue("exclude_hash", hash))
	}
	for _, s := range parseSorts(q) {
		hidden.WriteString(hiddenValue("sort", s.token()))
	}
	return `<form method="get" action="/results" class="row g-2 align-items-end mb-3">` +
		hidden.String() +
		`<div class="col-lg-6"><label class="form-label mb-1" for="search">Search</label>` +
		`<input class="form-control" id="search" name="search" value="` + html.EscapeString(q.Get("search")) + `" placeholder="URL, hash, or body"></div>` +
		`<div class="col-lg-3"><label class="form-label mb-1" for="status_code">Status code</label>` +
		`<input class="form-control" id="status_code" name="status_code" value="` + html.EscapeString(q.Get("status_code")) + `" placeholder="200 or 404"></div>` +
		`<div class="col-lg-auto d-flex flex-wrap gap-2">` +
		`<button class="btn btn-primary" type="submit">Apply</button>` +
		`<a class="btn btn-outline-secondary" href="` + html.EscapeString(resetFiltersURL(q.Get("dir"))) + `">Reset filters</a>` +
		refreshButton(q) +
		`<button type="button" class="btn btn-outline-secondary" onclick="document.getElementById('raw-query').classList.remove('d-none')">Raw</button>` +
		`</div></form>`
}

// renderRawQuery builds the form whose raw parameter replaces the results WHERE clause.
// where is the clause currently used to list rows, so the box starts from the active filters.
// The form stays hidden until Raw is clicked, unless raw is already in q. It returns that HTML.
func renderRawQuery(q url.Values, where string) string {
	class := "mt-2 d-none"
	if q.Get("raw") != "" {
		class = "mt-2"
	}
	var b strings.Builder
	b.WriteString(`<form id="raw-query" method="get" action="/results" class="` + class + ` mb-3">`)
	b.WriteString(hiddenValue("dir", q.Get("dir")))
	for _, s := range parseSorts(q) {
		b.WriteString(hiddenValue("sort", s.token()))
	}
	b.WriteString(`<label class="form-label mb-1" for="raw">Raw query</label>`)
	b.WriteString(`<input class="form-control font-monospace" id="raw" name="raw" value="` + html.EscapeString(where) + `">`)
	b.WriteString(`<button class="btn btn-primary mt-2" type="submit">Apply raw</button>`)
	b.WriteString(`</form>`)
	return b.String()
}

// renderResultsTable builds the summary links and the result rows for q.
// The root element is replaced when Refresh runs. It returns that HTML.
func renderResultsTable(q url.Values, page resultPage) string {
	status := strings.TrimSpace(q.Get("status_code"))
	var body strings.Builder
	body.WriteString(`<div id="results-table">`)
	body.WriteString(`<div class="d-flex flex-wrap gap-2 mb-3">`)
	body.WriteString(summaryLink(resultsURL(q, ""), "Total results", page.all, "btn-outline-dark", "btn-dark", status == ""))
	body.WriteString(summaryLink(resultsURL(q, "200"), "200 result", page.c200, "btn-outline-success", "btn-success", status == "200"))
	body.WriteString(summaryLink(resultsURL(q, "300"), "300 result", page.c300, "btn-outline-primary", "btn-primary", status == "300"))
	body.WriteString(summaryLink(resultsURL(q, "400"), "400 result", page.c400, "btn-outline-warning", "btn-warning", status == "400"))
	body.WriteString(summaryLink(resultsURL(q, "500"), "500 result", page.c500, "btn-outline-danger", "btn-danger", status == "500"))
	body.WriteString(`</div>`)
	body.WriteString(`<div class="card shadow-sm"><div class="table-responsive"><table class="table table-sm table-hover align-middle mb-0">`)
	body.WriteString(`<thead class="table-light"><tr>`)
	body.WriteString(`<th>#</th><th>Url</th><th>StatusCode</th><th>Hash</th><th>Latency</th><th>ContentLength</th><th>Body500</th><th></th><th class="hide-col"></th>`)
	body.WriteString(`</tr></thead>`)
	if len(page.rows) == 0 {
		body.WriteString(`<tbody><tr><td colspan="9" class="text-center text-secondary py-4">No results</td></tr></tbody>`)
	}
	for _, row := range page.rows {
		body.WriteString(renderResultRow(q, row))
	}
	body.WriteString(`</table></div></div></div>`)
	return body.String()
}

// refreshButton builds the control that reloads the results table with the filters in q.
// A results-refresh event from a pin uses the same request. It returns the button HTML.
func refreshButton(q url.Values) string {
	return `<button type="button" class="btn btn-outline-secondary" hx-get="` + html.EscapeString(tableURL(q)) + `" hx-target="#results-table" hx-swap="outerHTML" hx-trigger="click, results-refresh from:body">Refresh</button>`
}

// resetFiltersURL builds the results page for dir with search, status, exclusions, and sorts cleared.
// It returns a /results URL.
func resetFiltersURL(dir string) string {
	q := url.Values{}
	q.Set("dir", dir)
	return "/results?" + q.Encode()
}

// tableURL builds the table fragment request for the filters in q.
// It returns a /results/table URL.
func tableURL(q url.Values) string {
	return "/results/table?" + q.Encode()
}

// renderSortForm builds the form that reloads the results page in a chosen order.
// It keeps dir, search, status_code, and exclude_hash from q, and offers five sort slots.
// It returns the form HTML.
func renderSortForm(q url.Values) string {
	var b strings.Builder
	b.WriteString(`<form method="get" action="/results" class="row g-2 align-items-end mb-3">`)
	b.WriteString(hiddenValue("dir", q.Get("dir")))
	b.WriteString(hiddenValue("search", q.Get("search")))
	b.WriteString(hiddenValue("status_code", q.Get("status_code")))
	b.WriteString(hiddenValue("raw", q.Get("raw")))
	for _, hash := range q["exclude_hash"] {
		if hash == "" {
			continue
		}
		b.WriteString(hiddenValue("exclude_hash", hash))
	}
	sorts := parseSorts(q)
	for i := 0; i < maxResultSorts; i++ {
		selected := ""
		if i < len(sorts) {
			selected = sorts[i].token()
		}
		n := strconv.Itoa(i + 1)
		b.WriteString(`<div class="col-6 col-lg-auto"><label class="form-label mb-1" for="sort_` + n + `">Sort ` + n + `</label>`)
		b.WriteString(`<select class="form-select" id="sort_` + n + `" name="sort">`)
		b.WriteString(sortChoice("", "None", selected))
		for _, opt := range sortOptions() {
			b.WriteString(sortChoice(opt.Field+":asc", opt.Label+" ASC", selected))
			b.WriteString(sortChoice(opt.Field+":desc", opt.Label+" DESC", selected))
		}
		b.WriteString(`</select></div>`)
	}
	b.WriteString(`<div class="col-auto"><button class="btn btn-primary" type="submit">Sort</button></div></form>`)
	return b.String()
}

// hiddenValue builds one hidden input.
// It returns the input HTML.
func hiddenValue(name, value string) string {
	return `<input type="hidden" name="` + html.EscapeString(name) + `" value="` + html.EscapeString(value) + `">`
}

// sortChoice builds one option for a sort select.
// selected marks the option when it equals value. It returns the option HTML.
func sortChoice(value, label, selected string) string {
	sel := ""
	if value == selected {
		sel = ` selected`
	}
	return `<option value="` + html.EscapeString(value) + `"` + sel + `>` + html.EscapeString(label) + `</option>`
}

// renderJobStatus builds the polling card for the job named dir.
// It shows processed, left, errors, and a remaining-time estimate from the gap and average latency.
// The card requests itself every 2 seconds. It returns the card HTML.
func renderJobStatus(dir string) string {
	var b strings.Builder
	b.WriteString(`<div class="card shadow-sm mb-3"` + jobStatusPollAttrs(dir) + `><div class="card-body py-2 px-3 d-flex flex-wrap gap-4 align-items-baseline">`)
	b.WriteString(`<div class="fw-semibold">Status</div>`)
	job, err := jobByName(dir)
	if err != nil {
		b.WriteString(`<span class="text-warning">` + html.EscapeString(err.Error()) + `</span></div></div>`)
		return b.String()
	}
	status, err := jobStatus(dir)
	if err != nil {
		b.WriteString(`<span class="text-warning">` + html.EscapeString(err.Error()) + `</span></div></div>`)
		return b.String()
	}
	state := displayJobStatus(job.CurrentStatus, status.Left)
	b.WriteString(jobStateBadge(state))
	b.WriteString(statusStat("Processed", strconv.Itoa(status.Processed), "text-success"))
	b.WriteString(statusStat("Left", strconv.Itoa(status.Left), "text-primary"))
	b.WriteString(statusStat("Errors", strconv.Itoa(status.Errors), "text-danger"))
	remaining, basis := remainingText(job, status)
	b.WriteString(statusStat("Remaining", remaining, ""))
	if basis != "" {
		b.WriteString(`<div class="text-secondary small">` + html.EscapeString(basis) + `</div>`)
	}
	b.WriteString(jobControlButtons(dir, state))
	b.WriteString(`</div></div>`)
	return b.String()
}

// jobStatusPollAttrs builds the htmx attributes that refresh the status card.
// It returns the attribute text, including the leading space.
func jobStatusPollAttrs(dir string) string {
	q := url.Values{}
	q.Set("dir", dir)
	return ` id="job-status" hx-get="` + html.EscapeString("/results/status?"+q.Encode()) + `" hx-trigger="every 2s, job-status from:body" hx-swap="outerHTML"`
}

// displayJobStatus picks the status shown on the card.
// A job with nothing left is completed. An empty stored status is stopped. It returns stopped, processing, or completed.
func displayJobStatus(stored string, left int) string {
	if left <= 0 {
		return jobStatusCompleted
	}
	switch stored {
	case jobStatusProcessing, jobStatusStopped:
		return stored
	default:
		return jobStatusStopped
	}
}

// jobStateBadge builds the colored status label for state.
// It returns the span HTML.
func jobStateBadge(state string) string {
	class := "text-bg-secondary"
	label := "Stopped"
	switch state {
	case jobStatusProcessing:
		class = "text-bg-primary"
		label = "Processing"
	case jobStatusCompleted:
		class = "text-bg-success"
		label = "Completed"
	}
	return `<span class="badge ` + class + `">` + label + `</span>`
}

// jobControlButtons builds the Resume or Stop button for the status card.
// Processing shows Stop. Stopped shows Resume. Completed shows neither.
// It returns the button group HTML, or an empty string when there is no button.
func jobControlButtons(dir, state string) string {
	q := url.Values{}
	q.Set("dir", dir)
	enc := q.Encode()
	var button string
	switch state {
	case jobStatusProcessing:
		button = jobControlButton("Stop", "btn-outline-danger", "/stopjob?"+enc)
	case jobStatusStopped:
		button = jobControlButton("Resume", "btn-outline-primary", "/resumejob?"+enc)
	default:
		return ""
	}
	return `<div class="ms-auto d-flex gap-1">` + button + `</div>`
}

// jobControlButton builds one status-card button that posts to href.
// It returns the button HTML.
func jobControlButton(label, class, href string) string {
	return `<button type="button" class="btn btn-sm ` + class + `" hx-post="` + html.EscapeString(href) + `" hx-swap="none">` + html.EscapeString(label) + `</button>`
}

// statusStat builds one labeled number inside the status card.
// It returns the div HTML.
func statusStat(label, value, valueClass string) string {
	class := "fw-semibold"
	if valueClass != "" {
		class += " " + valueClass
	}
	return `<div><span class="text-secondary me-1">` + html.EscapeString(label) + `</span><span class="` + class + `">` + html.EscapeString(value) + `</span></div>`
}

// remainingText estimates how long the requests still left for job will take.
// The estimate is the midpoint of the gap for each pause, plus the average latency for each request still left.
// It returns the short remaining label and the inputs used for that estimate.
func remainingText(job models.Job, status jobStatusBody) (string, string) {
	gapMin, gapMax, err := parseGap(job.Gap)
	if err != nil {
		return "unavailable", ""
	}
	avg, err := averageLatency(job.Id)
	if err != nil {
		return "unavailable", ""
	}
	basis := "gap " + formatGap(gapMin, gapMax)
	if status.Processed == 0 {
		basis += ", avg latency unknown"
	} else {
		basis += ", avg latency " + formatLatency(int(avg+0.5))
	}
	return formatRemaining(status.Left, remainingDuration(status.Left, gapMin, gapMax, avg)), basis
}

// remainingDuration estimates the time left for left requests.
// gapMin and gapMax are the job pause bounds in seconds. avgLatencyNs is the mean stored latency.
// Pauses use the midpoint and apply between requests, so the last request adds no pause. It returns that duration.
func remainingDuration(left, gapMin, gapMax int, avgLatencyNs float64) time.Duration {
	if left <= 0 {
		return 0
	}
	midNs := (float64(gapMin) + float64(gapMax)) / 2 * float64(time.Second)
	total := midNs*float64(left-1) + avgLatencyNs*float64(left)
	if total < 0 {
		return 0
	}
	return time.Duration(total)
}

// formatRemaining renders d as a short remaining-time label.
// left at or below zero returns done. A positive duration under one second returns under 1s.
func formatRemaining(left int, d time.Duration) string {
	if left <= 0 {
		return "done"
	}
	if d < time.Second {
		return "under 1s"
	}
	d = d.Round(time.Second)
	var parts []string
	if h := d / time.Hour; h > 0 {
		parts = append(parts, strconv.FormatInt(int64(h), 10)+"h")
		d -= h * time.Hour
	}
	if m := d / time.Minute; m > 0 {
		parts = append(parts, strconv.FormatInt(int64(m), 10)+"m")
		d -= m * time.Minute
	}
	if s := d / time.Second; s > 0 || len(parts) == 0 {
		parts = append(parts, strconv.FormatInt(int64(s), 10)+"s")
	}
	return "about " + strings.Join(parts, " ")
}

// formatGap renders a min:max pause as seconds.
// Equal bounds return one number. It returns that text.
func formatGap(min, max int) string {
	if min == max {
		return strconv.Itoa(min) + "s"
	}
	return strconv.Itoa(min) + "–" + strconv.Itoa(max) + "s"
}

// renderExcluded builds a badge for each exclude_hash value in q.
// Each badge links to the same page with that one hash removed. It returns an empty string when nothing is excluded.
func renderExcluded(q url.Values) string {
	hashes := q["exclude_hash"]
	if len(hashes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="mb-3"><span class="text-secondary me-2">Excluded hashes</span>`)
	for _, hash := range hashes {
		if hash == "" {
			continue
		}
		label := hash
		if len(label) > 12 {
			label = label[:12] + "…"
		}
		b.WriteString(`<a class="badge text-bg-secondary text-decoration-none me-1" href="` + html.EscapeString(withoutExcludeHash(q, hash)) + `" title="` + html.EscapeString(hash) + `">` + html.EscapeString(label) + ` ×</a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// summaryLink builds one of the total, 200, 300, 400, or 500 links above the table.
// href is the destination. count is the badge number. outline and solid are Bootstrap button classes, and active uses the solid style.
// It returns the anchor HTML.
func summaryLink(href, label string, count int, outline, solid string, active bool) string {
	class := "btn btn-sm " + outline
	badge := "badge rounded-pill ms-1 " + strings.Replace(solid, "btn-", "text-bg-", 1)
	if active {
		class = "btn btn-sm " + solid
		badge = "badge rounded-pill ms-1 text-bg-light"
	}
	return `<a class="` + class + `" href="` + html.EscapeString(href) + `">` +
		html.EscapeString(label) + ` <span class="` + badge + `">` + strconv.Itoa(count) + `</span></a>`
}

// renderResultRow builds one result's table body, with the data row and the empty detail row under it.
// q supplies the current filters for the exclude-hash link. It returns that tbody.
func renderResultRow(q url.Values, row models.Result) string {
	id := strconv.Itoa(row.Id)
	detailID := "detail-" + id
	dir := q.Get("dir")
	buttons := detailButton("FullUrl", detailURL(dir, row.Id, "full_url"), detailID) +
		openFileButton("ResponseFile", fileURL(dir, row.Id, "response")) +
		openFileButton("Shot", fileURL(dir, row.Id, "shot")) +
		detailButton("Queries", detailURL(dir, row.Id, "queries"), detailID) +
		detailButton("RequestBody", detailURL(dir, row.Id, "request_body"), detailID) +
		detailButton("RequestHeaders", detailURL(dir, row.Id, "request_headers"), detailID) +
		detailButton("ResponseHeaders", detailURL(dir, row.Id, "response_headers"), detailID) +
		detailButton("ResponseBody", detailURL(dir, row.Id, "response_body"), detailID) +
		`<a class="btn btn-sm btn-outline-danger" href="` + html.EscapeString(excludeHashURL(q, row.ResponseHash)) + `">Exclude hash</a>` +
		pinButton(dir, row)
	rowClass := ""
	if row.IsPin {
		rowClass = ` class="pinned"`
	}
	return `<tbody id="result-` + id + `"><tr` + rowClass + `>` +
		`<td>` + strconv.Itoa(row.Index) + `</td>` +
		`<td class="text-break">` + html.EscapeString(row.Url) + `</td>` +
		`<td>` + statusBadge(row.StatusCode) + `</td>` +
		`<td class="text-break"><code class="small">` + html.EscapeString(row.ResponseHash) + `</code></td>` +
		`<td class="text-nowrap">` + html.EscapeString(formatLatency(row.Latency)) + `</td>` +
		`<td class="text-nowrap">` + strconv.Itoa(row.ContentLength) + `</td>` +
		`<td class="body500"><div class="small text-break">` + html.EscapeString(row.Body500) + `</div></td>` +
		`<td><div class="d-flex flex-wrap gap-1">` + buttons + `</div></td>` +
		`<td class="hide-col">` + hideButton(dir, row.Id) + `</td>` +
		`</tr>` +
		`<tr class="detail` + pinnedClass(row.IsPin) + `"><td colspan="9" id="` + detailID + `" class="p-0"></td></tr></tbody>`
}

// pinnedClass returns the pinned row class, including the leading space, when pinned is true.
// It returns an empty string otherwise.
func pinnedClass(pinned bool) string {
	if !pinned {
		return ""
	}
	return " pinned"
}

// pinButton builds the control that sets or clears IsPin on row.
// A pinned row shows Unpin. It returns the button HTML.
func pinButton(dir string, row models.Result) string {
	if row.IsPin {
		return `<button type="button" class="btn btn-sm btn-warning" hx-post="` + html.EscapeString(pinURL(dir, row.Id, false)) + `" hx-swap="none">Unpin</button>`
	}
	return `<button type="button" class="btn btn-sm btn-outline-warning" hx-post="` + html.EscapeString(pinURL(dir, row.Id, true)) + `" hx-swap="none">Pin</button>`
}

// pinURL builds the request that pins or unpins result id.
// pin false clears IsPin. It returns a /results/pin URL.
func pinURL(dir string, id int, pin bool) string {
	q := url.Values{}
	q.Set("dir", dir)
	q.Set("id", strconv.Itoa(id))
	if pin {
		q.Set("pin", "1")
	} else {
		q.Set("pin", "0")
	}
	return "/results/pin?" + q.Encode()
}

// hideButton builds the control that removes result id from the table.
// The response is empty and replaces the result's tbody. It returns the button HTML.
func hideButton(dir string, id int) string {
	return `<button type="button" class="btn btn-outline-danger" title="Remove" hx-get="` + html.EscapeString(hideURL(dir, id)) + `" hx-target="#result-` + strconv.Itoa(id) + `" hx-swap="outerHTML">×</button>`
}

// hideURL builds the request that removes result id from the table.
// It returns a /results/hide URL.
func hideURL(dir string, id int) string {
	q := url.Values{}
	q.Set("dir", dir)
	q.Set("id", strconv.Itoa(id))
	return "/results/hide?" + q.Encode()
}

// detailButton builds a button that appends href into the element with id target.
// A later click adds another block under the ones already shown. It returns the button HTML.
func detailButton(label, href, target string) string {
	return `<button type="button" class="btn btn-sm btn-outline-secondary" hx-get="` + html.EscapeString(href) + `" hx-target="#` + html.EscapeString(target) + `" hx-swap="beforeend">` + html.EscapeString(label) + `</button>`
}

// openFileButton builds a button that opens href in a new tab.
// It returns the anchor HTML.
func openFileButton(label, href string) string {
	return `<a class="btn btn-sm btn-outline-secondary" href="` + html.EscapeString(href) + `" target="_blank" rel="noopener">` + html.EscapeString(label) + `</a>`
}

// statusBadge builds a colored badge for an HTTP status code.
// It returns the span HTML.
func statusBadge(code int) string {
	class := "text-bg-secondary"
	switch {
	case code >= 200 && code < 300:
		class = "text-bg-success"
	case code >= 300 && code < 400:
		class = "text-bg-primary"
	case code >= 400 && code < 500:
		class = "text-bg-warning"
	case code >= 500 && code < 600:
		class = "text-bg-danger"
	}
	return `<span class="badge ` + class + `">` + strconv.Itoa(code) + `</span>`
}

// renderDetailFragment builds the block shown in a result's detail row.
// failed shows text as a warning. Blank text shows "empty". It returns the fragment HTML.
func renderDetailFragment(title, text string, failed bool) string {
	var body string
	if failed {
		body = `<div class="alert alert-warning mb-0">` + html.EscapeString(text) + `</div>`
	} else if strings.TrimSpace(text) == "" {
		body = `<div class="text-secondary">empty</div>`
	} else {
		body = `<pre class="detail-pre mb-0">` + html.EscapeString(text) + `</pre>`
	}
	return `<div class="detail-body p-3 bg-body-tertiary border-top">` +
		`<div class="fw-semibold mb-2">` + html.EscapeString(title) + `</div>` +
		body +
		`</div>`
}

// detailContent picks the text for one detail button.
// part is full_url, queries, request_body, request_headers, response_headers, or response_body.
// It returns the heading, the text, and true when that text is an error message.
func detailContent(row ResultView, part string) (string, string, bool) {
	switch part {
	case "full_url":
		return "FullUrl", formatFullURL(row), false
	case "queries":
		if row.QueriesRaw != "" {
			return "Queries", row.QueriesRaw, false
		}
		return "Queries", formatQueries(row.Queries), false
	case "request_body":
		return "RequestBody", row.Body, false
	case "request_headers":
		if row.HeadersRaw != "" {
			return "RequestHeaders", row.HeadersRaw, false
		}
		return "RequestHeaders", formatStringMap(row.Headers), false
	case "response_headers":
		text, err := readStoredFile(row.ResposneHeaders)
		if err != nil {
			return "ResponseHeaders", err.Error(), true
		}
		return "ResponseHeaders", text, false
	case "response_body":
		text, err := readStoredFile(row.ResponseFile)
		if err != nil {
			return "ResponseBody", err.Error(), true
		}
		return "ResponseBody", text, false
	default:
		return "Error", "unknown part", true
	}
}

// formatFullURL renders the request method and the URL with its scheme and path.
// The query string is left off. It returns a single "METHOD scheme://host/path" line.
func formatFullURL(row ResultView) string {
	scheme := "http"
	if row.Https {
		scheme = "https"
	}
	method := strings.ToUpper(strings.TrimSpace(row.Method))
	if method == "" {
		method = "GET"
	}
	u := url.URL{
		Scheme: scheme,
		Host:   row.DomainName,
		Path:   requestPath(row.Uri),
	}
	return method + " " + u.String()
}

// requestPath returns uri as a URL path with no query string.
// A missing leading slash is added. It returns "/" when uri is blank.
func requestPath(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return "/"
	}
	if !strings.HasPrefix(uri, "/") {
		return "/" + uri
	}
	return uri
}

// formatQueries renders query parameters as key=value lines, with the keys sorted.
// It returns an empty string when m has no entries.
func formatQueries(m map[string][]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		values := m[key]
		if len(values) == 0 {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(key)
			continue
		}
		for _, value := range values {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(key)
			b.WriteByte('=')
			b.WriteString(value)
		}
	}
	return b.String()
}

// formatStringMap renders headers as "Name: value" lines, sorted by name.
// Each value of a header is its own line. It returns an empty string when m has no entries.
func formatStringMap(m map[string][]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		values := m[key]
		if len(values) == 0 {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(key)
			b.WriteString(":")
			continue
		}
		for _, value := range values {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(key)
			b.WriteString(": ")
			b.WriteString(value)
		}
	}
	return b.String()
}

// readStoredFile reads a response body or response header file for display.
// It returns at most 1 MiB, and appends a truncation note when the file is longer.
func readStoredFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", os.ErrNotExist
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const max = 1 << 20
	buf := make([]byte, max+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", err
	}
	if n > max {
		return string(buf[:max]) + "\n\n[truncated]", nil
	}
	return string(buf[:n]), nil
}

// formatLatency converts a latency stored in nanoseconds into a millisecond string.
// Values under 100 ms keep one decimal place. It returns that string.
func formatLatency(ns int) string {
	if ns < 0 {
		ns = 0
	}
	ms := float64(ns) / float64(time.Millisecond)
	if ms < 100 {
		return strconv.FormatFloat(ms, 'f', 1, 64) + " ms"
	}
	return strconv.FormatInt(int64(ms+0.5), 10) + " ms"
}

// resultFile resolves the file a result button opens.
// kind is response or shot. It returns the absolute path and, for a shot, application/json.
// The response content type is left empty so the file bytes can be sniffed.
// It returns an error when kind is unknown or the path is outside the job directory.
func resultFile(dir string, row ResultView, kind string) (string, string, error) {
	switch kind {
	case "response":
		path, err := pathInsideDir(dir, row.ResponseFile)
		return path, "", err
	case "shot":
		path, err := pathInsideDir(dir, filepath.Join(dir, "processed", strconv.Itoa(row.Index)+".json"))
		return path, "application/json; charset=utf-8", err
	default:
		return "", "", errors.New("unknown kind")
	}
}

// pathInsideDir returns the absolute form of path when it stays inside dir.
// It returns an error when path is empty, escapes dir, or either path cannot be resolved.
func pathInsideDir(dir, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", os.ErrNotExist
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("file is outside the job directory")
	}
	return abs, nil
}

// serveResultFile writes the file at path as the HTTP response.
// An empty contentType is replaced by sniffing the first 512 bytes.
// The response is sandboxed so opened HTML cannot use this server's origin.
func serveResultFile(w http.ResponseWriter, r *http.Request, path, contentType string) {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	if contentType == "" {
		buf := make([]byte, 512)
		n, readErr := io.ReadFull(f, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			http.Error(w, readErr.Error(), http.StatusInternalServerError)
			return
		}
		contentType = http.DetectContentType(buf[:n])
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

// fileURL builds the request that opens one stored file for result id.
// kind is response or shot. It returns a /results/file URL.
func fileURL(dir string, id int, kind string) string {
	q := url.Values{}
	q.Set("dir", dir)
	q.Set("id", strconv.Itoa(id))
	q.Set("kind", kind)
	return "/results/file?" + q.Encode()
}

// detailURL builds the request htmx uses to load one field of result id.
// part selects the field. It returns a /results/detail URL.
func detailURL(dir string, id int, part string) string {
	q := url.Values{}
	q.Set("dir", dir)
	q.Set("id", strconv.Itoa(id))
	q.Set("part", part)
	return "/results/detail?" + q.Encode()
}

// resultsURL copies q and sets its status_code filter to status.
// An empty status removes the filter. Other query values stay. It returns a /results URL.
func resultsURL(q url.Values, status string) string {
	next := cloneQuery(q)
	if status == "" {
		next.Del("status_code")
	} else {
		next.Set("status_code", status)
	}
	return "/results?" + next.Encode()
}

// excludeHashURL copies q and adds hash to exclude_hash unless that hash is already there.
// It returns a /results URL.
func excludeHashURL(q url.Values, hash string) string {
	next := cloneQuery(q)
	for _, existing := range next["exclude_hash"] {
		if existing == hash {
			return "/results?" + next.Encode()
		}
	}
	next.Add("exclude_hash", hash)
	return "/results?" + next.Encode()
}

// withoutExcludeHash copies q and removes one occurrence of hash from exclude_hash.
// It returns a /results URL.
func withoutExcludeHash(q url.Values, hash string) string {
	next := cloneQuery(q)
	values := append([]string(nil), next["exclude_hash"]...)
	next.Del("exclude_hash")
	removed := false
	for _, value := range values {
		if !removed && value == hash {
			removed = true
			continue
		}
		next.Add("exclude_hash", value)
	}
	return "/results?" + next.Encode()
}

// cloneQuery returns a copy of q.
// Changing the copy does not change the original query.
func cloneQuery(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for key, values := range q {
		out[key] = append([]string(nil), values...)
	}
	return out
}
