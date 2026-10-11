package finding

import (
	"strings"

	"github.com/linn221/attacker/models"
)

type Finding struct {
	Rule        string
	Severity    string
	Evidence    string
	Description string
}

type Detector interface {
	Detect(r *models.Result) []Finding
}

type DirectoryListingDetector struct{}

func (d DirectoryListingDetector) Detect(r *models.Result) []Finding {
	body := strings.ToLower(r.Body500)

	patterns := []string{
		"index of /",
		"directory listing for /",
		"parent directory",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return []Finding{{
				Rule:        "directory-listing",
				Severity:    "medium",
				Evidence:    pattern,
				Description: "Possible directory listing page",
			}}
		}
	}

	return nil
}
