package models

import "maps"

type Configuration struct {
	Https      *bool               `yaml:"https,omitempty"`
	DomainName *string             `yaml:"domainName,omitempty"`
	Uri        *string             `yaml:"uri,omitempty"`
	Method     *string             `yaml:"method,omitempty"`
	Headers    map[string]string   `yaml:"headers,omitempty"`
	Cookies    map[string]string   `yaml:"cookies,omitempty"`
	Queries    map[string][]string `yaml:"queries,omitempty"`
	Body       *string             `yaml:"body,omitempty"`
	BodyJson   any                 `yaml:"bodyJson,omitempty"`
	BodyForm   map[string][]string `yaml:"bodyForm,omitempty"`
}

// Ptr returns a pointer to v for Configuration composite literals.
func Ptr[T any](v T) *T {
	return &v
}

// Shot copies base and overlays the fields this configuration sets.
func (cfg *Configuration) Shot(base Shot) Shot {
	result := base.Clone()
	if cfg.Https != nil {
		result.Https = *cfg.Https
	}

	if cfg.DomainName != nil {
		result.DomainName = *cfg.DomainName
	}

	if cfg.Uri != nil {
		result.Uri = *cfg.Uri
	}
	if cfg.Method != nil {
		result.Method = *cfg.Method
	}

	if cfg.Headers != nil {
		if result.Headers == nil {
			result.Headers = make(map[string]string, len(cfg.Headers))
		}
		maps.Copy(result.Headers, cfg.Headers)
	}

	if cfg.Queries != nil {
		if result.Queries == nil {
			result.Queries = make(map[string][]string, len(cfg.Queries))
		}
		maps.Copy(result.Queries, cfg.Queries)
	}

	if cfg.Cookies != nil {
		if result.Cookies == nil {
			result.Cookies = make(map[string][]string, len(cfg.Cookies))
		}
		for name, value := range cfg.Cookies {
			result.Cookies[name] = []string{value}
		}
	}

	if cfg.Body != nil {
		result.Body = *cfg.Body
	}

	return result
}
