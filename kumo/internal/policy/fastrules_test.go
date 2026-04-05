package policy

import (
	"testing"
)

func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		// Single segment wildcard
		{"/v1/candidates/*", "/v1/candidates/123", true},
		{"/v1/candidates/*", "/v1/candidates/abc", true},
		{"/v1/candidates/*", "/v1/candidates/123/notes", false},
		{"/v1/candidates/*", "/v1/candidates", false},

		// Multi-segment wildcard
		{"/v1/candidates/**", "/v1/candidates/123", true},
		{"/v1/candidates/**", "/v1/candidates/123/notes", true},
		{"/v1/candidates/**", "/v1/candidates/123/notes/456", true},

		// Mixed wildcards
		{"/v1/candidates/*/notes", "/v1/candidates/123/notes", true},
		{"/v1/candidates/*/notes", "/v1/candidates/abc/notes", true},
		{"/v1/candidates/*/notes", "/v1/candidates/123/other", false},

		// Nested wildcards
		{"/v1/candidates/*/interviews/*/feedback", "/v1/candidates/123/interviews/456/feedback", true},
		{"/v1/candidates/*/interviews/*/feedback", "/v1/candidates/123/interviews/feedback", false},

		// Exact match
		{"/v1/health", "/v1/health", true},
		{"/v1/health", "/v1/healthz", false},
		{"/v1/health", "/v1/health/deep", false},

		// Root
		{"/", "/", true},

		// Special regex chars in path
		{"/v1/users/*/settings.json", "/v1/users/123/settings.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			re, err := globToRegex(tt.pattern)
			if err != nil {
				t.Fatalf("globToRegex(%q) error: %v", tt.pattern, err)
			}
			got := re.MatchString(tt.path)
			if got != tt.match {
				t.Errorf("globToRegex(%q).MatchString(%q) = %v, want %v", tt.pattern, tt.path, got, tt.match)
			}
		})
	}
}

func TestCanonicalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/v1/candidates/123", "/v1/candidates/123"},
		{"/v1/candidates/123/", "/v1/candidates/123"},
		{"/v1//candidates///123", "/v1/candidates/123"},
		{"/v1/candidates/123?page=1", "/v1/candidates/123"},
		{"/v1/candidates/hello%20world", "/v1/candidates/hello world"},
		{"/", "/"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalizePath(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCompiledFastRuleMatch(t *testing.T) {
	rules := []FastRule{
		{
			Name:   "allow_github_read",
			Action: "allow",
			Match: RuleMatch{
				Hosts:   []string{"api.github.com"},
				Methods: []string{"GET"},
				Paths:   []string{"/repos/*", "/repos/*/issues"},
			},
		},
		{
			Name:   "block_delete",
			Action: "block",
			Match: RuleMatch{
				Methods: []string{"DELETE"},
			},
			Message: "DELETE requests are not allowed.",
		},
		{
			Name:   "allow_all_slack",
			Action: "allow",
			Match: RuleMatch{
				Hosts: []string{"hooks.slack.com"},
			},
		},
	}

	compiled, err := CompileFastRules(rules)
	if err != nil {
		t.Fatalf("CompileFastRules error: %v", err)
	}

	tests := []struct {
		name   string
		host   string
		method string
		path   string
		rule   int  // expected matching rule index, -1 for no match
		match  bool
	}{
		{"github GET repos", "api.github.com", "GET", "/repos/foo", 0, true},
		{"github GET issues", "api.github.com", "GET", "/repos/foo/issues", 0, true},
		{"github POST repos", "api.github.com", "POST", "/repos/foo", -1, false},
		{"github GET users", "api.github.com", "GET", "/users/bar", -1, false},
		{"any DELETE", "api.github.com", "DELETE", "/anything", 1, true},
		{"slack any", "hooks.slack.com", "POST", "/services/T123", 2, true},
		{"unknown host", "api.unknown.com", "GET", "/something", -1, false},
		{"github with port", "api.github.com:443", "GET", "/repos/foo", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := false
			matchIdx := -1
			for i, cr := range compiled {
				if cr.Match(tt.host, tt.method, tt.path) {
					matched = true
					matchIdx = i
					break
				}
			}
			if matched != tt.match {
				t.Errorf("match = %v, want %v", matched, tt.match)
			}
			if matchIdx != tt.rule {
				t.Errorf("matched rule %d, want %d", matchIdx, tt.rule)
			}
		})
	}
}
