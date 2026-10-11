package main

const (
	jobStatusStopped    = "stopped"
	jobStatusProcessing = "processing"
	jobStatusCompleted  = "completed"
)

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
	Headers         map[string][]string
	HeadersRaw      string
	Cookies         map[string][]string
	Queries         map[string][]string
	QueriesRaw      string
	Body            string
	StatusCode      int
	Body500         string
	ResponseHash    string
	Latency         int
	ResponseFile    string
	ResposneHeaders string
	IsPin           bool
}
