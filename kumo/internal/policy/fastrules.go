package policy

import (
	"net/url"
	"regexp"
	"strings"
)

// CompiledFastRule is a FastRule with pre-compiled path patterns.
type CompiledFastRule struct {
	Rule     FastRule
	Hosts    map[string]bool
	Methods  map[string]bool
	Patterns []*regexp.Regexp
}

// CompileFastRules compiles glob patterns to regexes at load time.
func CompileFastRules(rules []FastRule) ([]CompiledFastRule, error) {
	compiled := make([]CompiledFastRule, 0, len(rules))

	for _, rule := range rules {
		cr := CompiledFastRule{
			Rule:    rule,
			Hosts:   toSet(rule.Match.Hosts),
			Methods: toSetUpper(rule.Match.Methods),
		}

		for _, pattern := range rule.Match.Paths {
			re, err := globToRegex(pattern)
			if err != nil {
				return nil, err
			}
			cr.Patterns = append(cr.Patterns, re)
		}

		compiled = append(compiled, cr)
	}

	return compiled, nil
}

// Match checks if a request matches this compiled rule.
func (cr *CompiledFastRule) Match(host, method, path string) bool {
	// Canonicalize path before matching
	path = canonicalizePath(path)

	// Check host (if hosts specified)
	if len(cr.Hosts) > 0 {
		// Strip port from host for matching
		h := host
		if idx := strings.LastIndex(h, ":"); idx != -1 {
			h = h[:idx]
		}
		if !cr.Hosts[h] {
			return false
		}
	}

	// Check method (if methods specified)
	if len(cr.Methods) > 0 && !cr.Methods[strings.ToUpper(method)] {
		return false
	}

	// Check path patterns (if patterns specified, any must match)
	if len(cr.Patterns) > 0 {
		matched := false
		for _, re := range cr.Patterns {
			if re.MatchString(path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// canonicalizePath normalizes a URL path before matching:
// - Decode percent-encoding
// - Remove trailing slashes (except root)
// - Collapse double slashes
// - Strip query parameters
func canonicalizePath(path string) string {
	// Strip query params
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Decode percent-encoding
	decoded, err := url.PathUnescape(path)
	if err == nil {
		path = decoded
	}

	// Collapse double slashes
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	// Remove trailing slash (except root)
	if len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}

	return path
}

// globToRegex converts a glob pattern like /v1/candidates/*/notes to a regex.
// * matches exactly one path segment
// ** matches one or more path segments
func globToRegex(pattern string) (*regexp.Regexp, error) {
	// Escape regex special chars, then convert glob wildcards
	var b strings.Builder
	b.WriteString("^")

	parts := strings.Split(pattern, "/")
	for i, part := range parts {
		if i > 0 {
			b.WriteString("/")
		}

		switch part {
		case "**":
			b.WriteString(".+") // one or more path segments
		case "*":
			b.WriteString("[^/]+") // exactly one path segment
		default:
			b.WriteString(regexp.QuoteMeta(part))
		}
	}

	b.WriteString("$")
	return regexp.Compile(b.String())
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

func toSetUpper(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[strings.ToUpper(item)] = true
	}
	return m
}
