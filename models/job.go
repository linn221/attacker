package models

// Job is one stored fuzz run.
// Name is the job directory. Title is the label shown with that directory. Rows stay in the jobs table.
type Job struct {
	Id            int    `gorm:"primaryKey"`
	Name          string `gorm:"uniqueIndex;not null"`
	Title         string
	Current       int
	End           int
	Gap           string
	CurrentStatus string
}

// TableName returns the SQLite table that stores Job rows.
func (Job) TableName() string { return "jobs" }
