package main

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/linn221/attacker/finding"
	"github.com/linn221/attacker/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var errJobNotFound = errors.New("job not found")

const databaseFile = "attacker.db"

var db *gorm.DB

// initDB opens attacker.db, creates the job and result tables, and keeps the connection for later calls.
// It returns an error if the file cannot be opened or the tables cannot be created.
func initDB() error {
	opened, err := gorm.Open(sqlite.Open(databaseFile), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	if err := opened.AutoMigrate(&JobModel{}, &models.Result{}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db = opened
	if err := settleJobStatuses(); err != nil {
		return err
	}
	if err := db.Exec("UPDATE results SET is_pin = 0 WHERE is_pin IS NULL").Error; err != nil {
		return fmt.Errorf("settle result pins: %w", err)
	}
	return nil
}

// settleJobStatuses records jobs that are not running as stopped, and finished jobs as completed.
// A process restart has no live runner, so a stored processing state becomes stopped. It returns an error if the update fails.
func settleJobStatuses() error {
	if err := db.Exec("UPDATE job_models SET current_status = ? WHERE current_status IS NULL OR current_status = '' OR current_status = ?", jobStatusStopped, jobStatusProcessing).Error; err != nil {
		return fmt.Errorf("settle job status: %w", err)
	}
	if err := db.Exec(`UPDATE job_models SET current_status = ? WHERE current > "end"`, jobStatusCompleted).Error; err != nil {
		return fmt.Errorf("settle completed jobs: %w", err)
	}
	return nil
}

// createJob inserts a job, or resets it when name already exists.
// name is the job directory. gap is the min:max pause between tasks, in seconds. end is the last task id.
// On reset, current goes back to 1 and end and gap are replaced. It returns the saved job.
func createJob(name, gap string, end int) (JobModel, error) {
	existing, err := jobByName(name)
	if err == nil {
		if err := db.Model(&existing).Updates(map[string]any{
			"current":        1,
			"end":            end,
			"gap":            gap,
			"current_status": jobStatusStopped,
		}).Error; err != nil {
			return JobModel{}, err
		}
		existing.Current = 1
		existing.End = end
		existing.Gap = gap
		existing.CurrentStatus = jobStatusStopped
		return existing, nil
	}
	if !errors.Is(err, errJobNotFound) {
		return JobModel{}, err
	}
	job := JobModel{Name: name, Current: 1, End: end, Gap: gap, CurrentStatus: jobStatusStopped}
	if err := db.Create(&job).Error; err != nil {
		return JobModel{}, err
	}
	return job, nil
}

// listJobs returns every stored job, newest first.
func listJobs() ([]JobModel, error) {
	var jobs []JobModel
	if err := db.Order("id desc").Find(&jobs).Error; err != nil {
		return nil, err
	}
	if jobs == nil {
		jobs = []JobModel{}
	}
	return jobs, nil
}

// jobByName loads the job whose name is the job directory.
// It returns errJobNotFound when no row has that name.
func jobByName(name string) (JobModel, error) {
	var job JobModel
	tx := db.Raw("SELECT * FROM job_models WHERE name = ? LIMIT 1", name).Scan(&job)
	if tx.Error != nil {
		return JobModel{}, tx.Error
	}
	if job.Id == 0 {
		return JobModel{}, fmt.Errorf("%w: %s", errJobNotFound, name)
	}
	return job, nil
}

// updateJobCurrent sets which task the job will run next.
// id is the job primary key. current is that next task id. It returns an error if the update fails.
func updateJobCurrent(id, current int) error {
	job := JobModel{Id: id}
	return db.Model(&job).Updates(map[string]any{"current": current}).Error
}

// updateJobStatus stores the job's current_status.
// status is stopped, processing, or completed. It returns an error if the update fails.
func updateJobStatus(id int, status string) error {
	job := JobModel{Id: id}
	return db.Model(&job).Update("current_status", status).Error
}

// setResultPinned stores whether result id is pinned.
// It returns an error if the update fails.
func setResultPinned(id int, pinned bool) error {
	row := models.Result{Id: id}
	return db.Model(&row).Update("is_pin", pinned).Error
}

// insertResult stores one finished task.
// jobID and taskID identify the job and the shot. method is the method that was actually sent.
// responseFile and responseHeaders are saved as absolute paths. Maps are stored as JSON strings.
// It returns an error if encoding or the insert fails.
func insertResult(jobID, taskID int, shot models.Shot, req *http.Request, resp *http.Response, body []byte, latency time.Duration, responseFile, responseHeaders string) error {
	headers, err := encodeStringMap(shot.Headers)
	if err != nil {
		return fmt.Errorf("encode headers: %w", err)
	}
	cookies, err := encodeValuesMap(shot.Cookies)
	if err != nil {
		return fmt.Errorf("encode cookies: %w", err)
	}
	queries, err := encodeValuesMap(shot.Queries)
	if err != nil {
		return fmt.Errorf("encode queries: %w", err)
	}
	absBody, err := filepath.Abs(responseFile)
	if err != nil {
		return fmt.Errorf("response file: %w", err)
	}
	absHeaders, err := filepath.Abs(responseHeaders)
	if err != nil {
		return fmt.Errorf("response headers: %w", err)
	}
	n := min(len(body), 500)
	sum := md5.Sum(body)
	row := models.Result{
		JobId:           jobID,
		Index:           taskID,
		Https:           shot.Https,
		DomainName:      shot.DomainName,
		Uri:             shot.Uri,
		Url:             req.URL.String(),
		Method:          req.Method,
		Headers:         headers,
		Cookies:         cookies,
		Queries:         queries,
		Body:            shot.Body,
		StatusCode:      resp.StatusCode,
		Body500:         string(body[:n]),
		BodyHash:        fmt.Sprintf("%x", sum),
		ContentType:     resp.Header.Get("Content-Type"),
		ContentLength:   len(body),
		Latency:         int(latency),
		ResponseFile:    absBody,
		ResposneHeaders: absHeaders,
	}
	if err := db.Create(&row).Error; err != nil {
		return fmt.Errorf("insert result: %w", err)
	}
	id := row.Id
	detectors := [...]finding.Detector{finding.DirectoryListingDetector{}, &finding.ErrorDetector{}}
	for _, d := range detectors {
		if findings := d.Detect(&row); len(findings) > 0 {
			db.Where("id = ?", id).UpdateColumn("IsPin", true)
			fmt.Println(json.Marshal(findings[0]))
		}
	}
	return nil
}

// resultViewByID loads the result with primary key id and restores Headers, Cookies, and Queries from their JSON columns.
// It returns an error when the row does not exist or a JSON column is invalid.
func resultViewByID(id int) (ResultView, error) {
	var row models.Result
	err := db.First(&row, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ResultView{}, fmt.Errorf("result %d not found", id)
	}
	if err != nil {
		return ResultView{}, err
	}
	return decodeResult(row)
}

// queryResults loads the result rows for one job using the /results filters.
// search matches the URL, body hash, and Body500, ignoring case. exclude drops those body hashes.
// status limits the returned rows: 200, 300, 400, and 500 mean that whole class, and any other number must match exactly. The summary counts ignore status.
// sorts order the unpinned rows. Pinned rows that match the same filters stay first, in id order. An empty sorts list orders unpinned rows by id. It returns the matching rows and those counts.
func queryResults(jobID int, search, status string, exclude []string, sorts []resultSort) (resultPage, error) {
	where, args := resultWhere(jobID, search, exclude, "")
	var counts struct {
		Total int
		C200  int
		C300  int
		C400  int
		C500  int
	}
	countSQL := `SELECT COUNT(*) AS total,
		COALESCE(SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END), 0) AS c200,
		COALESCE(SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END), 0) AS c300,
		COALESCE(SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END), 0) AS c400,
		COALESCE(SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END), 0) AS c500
		FROM results WHERE ` + where
	if err := db.Raw(countSQL, args...).Scan(&counts).Error; err != nil {
		return resultPage{}, err
	}
	rowWhere, rowArgs := resultWhere(jobID, search, exclude, status)
	var rows []models.Result
	if err := db.Raw("SELECT * FROM results WHERE "+rowWhere+" ORDER BY "+orderBy(sorts), rowArgs...).Scan(&rows).Error; err != nil {
		return resultPage{}, err
	}
	if rows == nil {
		rows = []models.Result{}
	}
	return resultPage{
		rows: rows,
		all:  counts.Total,
		c200: counts.C200,
		c300: counts.C300,
		c400: counts.C400,
		c500: counts.C500,
	}, nil
}

// resultWhere builds the SQL predicate for a result query.
// status is included only when it is not empty. Search, hash exclusions, and status all apply to pinned rows.
// It returns the clause without the WHERE keyword, plus the placeholder arguments in order.
func resultWhere(jobID int, search string, exclude []string, status string) (string, []any) {
	clauses := []string{"job_id = ?"}
	args := []any{jobID}
	search = strings.TrimSpace(search)
	if search != "" {
		pattern := "%" + escapeLike(search) + "%"
		clauses = append(clauses, "(LOWER(url) LIKE ? ESCAPE '\\' OR LOWER(body_hash) LIKE ? ESCAPE '\\' OR LOWER(body500) LIKE ? ESCAPE '\\')")
		args = append(args, pattern, pattern, pattern)
	}
	hashes := make([]string, 0, len(exclude))
	for _, hash := range exclude {
		if hash != "" {
			hashes = append(hashes, hash)
		}
	}
	if len(hashes) > 0 {
		marks := make([]string, len(hashes))
		for i, hash := range hashes {
			marks[i] = "?"
			args = append(args, hash)
		}
		clauses = append(clauses, "body_hash NOT IN ("+strings.Join(marks, ",")+")")
	}
	clauses, args = appendStatusClause(clauses, args, status)
	return strings.Join(clauses, " AND "), args
}

// appendStatusClause adds a status_code condition to clauses and args.
// An empty status changes nothing. A non-numeric status matches no rows.
// 200, 300, 400, and 500 match that class; any other code must match exactly.
// It returns the extended clause list and arguments.
func appendStatusClause(clauses []string, args []any, status string) ([]string, []any) {
	status = strings.TrimSpace(status)
	if status == "" {
		return clauses, args
	}
	want, err := strconv.Atoi(status)
	if err != nil {
		return append(clauses, "0"), args
	}
	switch want {
	case 200, 300, 400, 500:
		return append(clauses, "status_code >= ? AND status_code < ?"), append(args, want, want+100)
	default:
		return append(clauses, "status_code = ?"), append(args, want)
	}
}

// escapeLike prepares s for a SQL LIKE pattern.
// It lowercases s and escapes \, %, and _. It returns that text without the surrounding percent signs.
func escapeLike(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

const maxResultSorts = 5

// resultSort is one column in a result ORDER BY list.
// Field is the form value. Column is the SQL column. Desc selects descending order.
type resultSort struct {
	Field  string
	Column string
	Desc   bool
}

// sortOption is one column the results sort form can choose.
// Field is submitted by the form. Column is the SQL identifier used in ORDER BY.
type sortOption struct {
	Field  string
	Column string
	Label  string
}

// sortOptions returns the columns the results page can sort by, in form order.
// Body sorts the Body500 preview stored on the result.
func sortOptions() []sortOption {
	return []sortOption{
		{Field: "index", Column: "index", Label: "#"},
		{Field: "url", Column: "url", Label: "Url"},
		{Field: "status_code", Column: "status_code", Label: "StatusCode"},
		{Field: "hash", Column: "body_hash", Label: "Hash"},
		{Field: "latency", Column: "latency", Label: "Latency"},
		{Field: "content_length", Column: "content_length", Label: "ContentLength"},
		{Field: "body", Column: "body500", Label: "Body"},
	}
}

// parseSorts reads up to five sort values from q.
// Each value is field:asc or field:desc. Blank and unknown values are skipped.
// It returns the pairs in the order they should be applied.
func parseSorts(q url.Values) []resultSort {
	out := make([]resultSort, 0, maxResultSorts)
	for _, value := range q["sort"] {
		if len(out) == maxResultSorts {
			break
		}
		field, dir, ok := strings.Cut(value, ":")
		if !ok || (dir != "asc" && dir != "desc") {
			continue
		}
		if field == "id" {
			field = "index"
		}
		opt, ok := sortOptionByField(field)
		if !ok {
			continue
		}
		out = append(out, resultSort{
			Field:  opt.Field,
			Column: opt.Column,
			Desc:   dir == "desc",
		})
	}
	return out
}

// token returns the form value for s, such as id:asc.
func (s resultSort) token() string {
	if s.Desc {
		return s.Field + ":desc"
	}
	return s.Field + ":asc"
}

// sortOptionByField finds the sort column named field.
// It returns false when field is not one of the form values.
func sortOptionByField(field string) (sortOption, bool) {
	for _, opt := range sortOptions() {
		if opt.Field == field {
			return opt, true
		}
	}
	return sortOption{}, false
}

// orderBy builds an ORDER BY list from sorts.
// Only columns from sortOptions are included. Id ascending is added when the list does not already sort by id.
// Pinned rows that match the filters stay first, in id order. An unset pin is treated as unpinned, and the chosen sorts apply only to those rows.
// It returns the SQL text that follows ORDER BY.
func orderBy(sorts []resultSort) string {
	allowed := make(map[string]bool, len(sortOptions()))
	for _, opt := range sortOptions() {
		allowed[opt.Column] = true
	}
	parts := make([]string, 0, len(sorts)+1)
	seenID := false
	for _, s := range sorts {
		if !allowed[s.Column] {
			continue
		}
		dir := "ASC"
		if s.Desc {
			dir = "DESC"
		}
		parts = append(parts, `"`+s.Column+`" `+dir)
		if s.Column == "id" {
			seenID = true
		}
	}
	if !seenID {
		parts = append(parts, `"id" ASC`)
	}
	return `COALESCE("is_pin", 0) DESC, CASE WHEN COALESCE("is_pin", 0) = 1 THEN "id" END ASC, ` + strings.Join(parts, ", ")
}

// averageLatency returns the mean result latency for jobID, in nanoseconds.
// A job with no results returns 0.
func averageLatency(jobID int) (float64, error) {
	var row struct {
		Ns float64
	}
	err := db.Raw("SELECT COALESCE(AVG(latency), 0) AS ns FROM results WHERE job_id = ?", jobID).Scan(&row).Error
	return row.Ns, err
}

// countResults returns how many result rows are stored for jobID.
func countResults(jobID int) (int, error) {
	var n int
	err := db.Raw("SELECT COUNT(*) AS n FROM results WHERE job_id = ?", jobID).Scan(&n).Error
	return n, err
}

// decodeResult copies row into a ResultView and unmarshals Headers, Cookies, and Queries.
// It returns an error if any of those JSON columns is invalid.
func decodeResult(row models.Result) (ResultView, error) {
	headers, err := decodeStringMap(row.Headers)
	if err != nil {
		return ResultView{}, fmt.Errorf("result %d headers: %w", row.Id, err)
	}
	cookies, err := decodeValuesMap(row.Cookies)
	if err != nil {
		return ResultView{}, fmt.Errorf("result %d cookies: %w", row.Id, err)
	}
	queries, err := decodeValuesMap(row.Queries)
	if err != nil {
		return ResultView{}, fmt.Errorf("result %d queries: %w", row.Id, err)
	}
	return ResultView{
		Id:              row.Id,
		JobId:           row.JobId,
		Index:           row.Index,
		Https:           row.Https,
		DomainName:      row.DomainName,
		Uri:             row.Uri,
		Url:             row.Url,
		Method:          row.Method,
		Headers:         headers,
		Cookies:         cookies,
		Queries:         queries,
		Body:            row.Body,
		StatusCode:      row.StatusCode,
		Body500:         row.Body500,
		BodyHash:        row.BodyHash,
		Latency:         row.Latency,
		ResponseFile:    row.ResponseFile,
		ResposneHeaders: row.ResposneHeaders,
		IsPin:           row.IsPin,
	}, nil
}

// encodeStringMap turns a map[string]string into the JSON string stored on a result.
// A nil map becomes {}. It returns that JSON.
func encodeStringMap(m map[string]string) (string, error) {
	if m == nil {
		m = map[string]string{}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// encodeValuesMap turns a map[string][]string into the JSON string stored on a result.
// A nil map becomes {}. It returns that JSON.
func encodeValuesMap(m map[string][]string) (string, error) {
	if m == nil {
		m = map[string][]string{}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeStringMap restores a map[string]string from a result's JSON column.
// Empty or null JSON returns an empty map. It returns an error if s is not that JSON shape.
func decodeStringMap(s string) (map[string]string, error) {
	if s == "" || s == "null" {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

// decodeValuesMap restores a map[string][]string from a result's JSON column.
// Empty or null JSON returns an empty map. It returns an error if s is not that JSON shape.
func decodeValuesMap(s string) (map[string][]string, error) {
	if s == "" || s == "null" {
		return map[string][]string{}, nil
	}
	var m map[string][]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string][]string{}
	}
	return m, nil
}
