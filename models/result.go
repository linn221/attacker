package models

type Result struct {
	Id         int `gorm:"primaryKey"`
	JobId      int `gorm:"index"`
	Index      int // Id of Task
	Https      bool
	DomainName string
	Uri        string
	Url        string
	Method     string
	Headers    string `gorm:"type:text"` // JSON map[string]string
	Cookies    string `gorm:"type:text"` // JSON map[string][]string
	Queries    string `gorm:"type:text"` // JSON map[string][]string
	Body       string `gorm:"type:text"`

	StatusCode      int
	Body500         string `gorm:"type:text"`
	BodyHash        string
	ContentType     string
	ContentLength   int
	Latency         int
	ResponseFile    string `gorm:"type:text"`
	ResposneHeaders string `gorm:"type:text"`
	IsPin           bool
}

// TableName returns the SQLite table that stores Result rows.
func (Result) TableName() string { return "results" }
