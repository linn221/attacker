package main

const (
	jobStatusStopped    = "stopped"
	jobStatusProcessing = "processing"
	jobStatusCompleted  = "completed"
)

type JobModel struct {
	Id            int    `gorm:"primaryKey"`
	Name          string `gorm:"uniqueIndex;not null"`
	Current       int
	End           int
	Gap           string
	CurrentStatus string
}

// TableName returns the SQLite table that stores JobModel rows.
func (JobModel) TableName() string { return "job_models" }

// ResultView is a stored models.Result with JSON columns restored to maps.
type ResultView struct {
	Id              int
	JobId           int
	Index           int
	Https           bool
	DomainName      string
	Uri             string
	Url             string
	Method          string
	Headers         map[string]string
	Cookies         map[string][]string
	Queries         map[string][]string
	Body            string
	StatusCode      int
	Body500         string
	BodyHash        string
	Latency         int
	ResponseFile    string
	ResposneHeaders string
	IsPin           bool
}
