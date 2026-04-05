// Package analyzer implements auto-policy generation from observed traffic.
//
// Flow:
//   1. Read JSONL traffic logs
//   2. Group by (host, method, path_template)
//   3. Extract path templates using heuristics
//   4. Sample up to N representative requests per group
//   5. Generate policy YAML (LLM-powered in full version, heuristic for now)
package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kumo-ai/kumo/internal/policy"
	"github.com/kumo-ai/kumo/pkg/types"
	"gopkg.in/yaml.v3"
)

// patternGroup groups traffic entries by URL pattern.
type patternGroup struct {
	Host       string
	Method     string
	PathTemplate string
	Count      int
	Samples    []types.TrafficEntry
}

// Summarize reads traffic logs and generates a policy.
func Summarize(logDir string, outputPath string, maxSamples int) error {
	if maxSamples == 0 {
		maxSamples = 200
	}

	// Read all traffic entries
	entries, err := readTrafficLogs(logDir)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		return fmt.Errorf("Error: no traffic logs found in %s\nCause: the log directory is empty or contains no .jsonl files\nFix: run 'kumo serve --mode observe' first to collect traffic data", logDir)
	}

	// Group by pattern
	groups := groupByPattern(entries, maxSamples)

	// Generate policy from groups
	pol := generatePolicy(groups)

	// Write policy YAML
	data, err := yaml.Marshal(pol)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write policy to %s: %w", outputPath, err)
	}

	fmt.Printf("Analyzing %d requests...\n", len(entries))
	fmt.Printf("Grouped into %d URL patterns\n", len(groups))
	fmt.Printf("Policy written to %s (%d fast rules)\n", outputPath, len(pol.Rules.Fast))

	return nil
}

func readTrafficLogs(dir string) ([]types.TrafficEntry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "traffic-*.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("glob traffic files: %w", err)
	}

	var entries []types.TrafficEntry
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", f, err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB line buffer
		for scanner.Scan() {
			var entry types.TrafficEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				continue // skip malformed lines
			}
			entries = append(entries, entry)
		}
		file.Close()
	}

	return entries, nil
}

func groupByPattern(entries []types.TrafficEntry, maxSamples int) []patternGroup {
	groups := make(map[string]*patternGroup)

	for _, entry := range entries {
		template := extractPathTemplate(entry.Path)
		key := entry.Host + "|" + entry.Method + "|" + template

		g, ok := groups[key]
		if !ok {
			g = &patternGroup{
				Host:         entry.Host,
				Method:       entry.Method,
				PathTemplate: template,
			}
			groups[key] = g
		}

		g.Count++
		if len(g.Samples) < maxSamples {
			g.Samples = append(g.Samples, entry)
		}
	}

	// Sort by count descending
	result := make([]patternGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result
}

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numericRe = regexp.MustCompile(`^\d+$`)
	hexRe     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
)

// extractPathTemplate converts /v1/candidates/123/notes to /v1/candidates/*/notes
func extractPathTemplate(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if uuidRe.MatchString(part) || numericRe.MatchString(part) || hexRe.MatchString(part) {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}

func generatePolicy(groups []patternGroup) *policy.Policy {
	pol := &policy.Policy{
		Version:     1,
		Name:        "auto-generated-policy",
		Description: fmt.Sprintf("Auto-generated from %d URL patterns", len(groups)),
		Rules: policy.RuleSet{
			Default: "flag",
		},
		Ban: policy.BanConfig{
			MaxViolations: 3,
			BanDuration:   "1h",
			Message:       "You have been temporarily suspended for attempting to circumvent security restrictions.",
		},
	}

	for i, g := range groups {
		// Strip port from host for cleaner rules
		host := g.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			hostPart := host[:idx]
			if hostPart != "" {
				host = hostPart
			}
		}

		rule := policy.FastRule{
			Name:   fmt.Sprintf("rule_%d_%s_%s", i+1, strings.ToLower(g.Method), sanitizeName(host)),
			Action: "allow",
			Match: policy.RuleMatch{
				Hosts:   []string{host},
				Methods: []string{g.Method},
				Paths:   []string{g.PathTemplate},
			},
		}
		pol.Rules.Fast = append(pol.Rules.Fast, rule)
	}

	return pol
}

func sanitizeName(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	if len(s) > 30 {
		s = s[:30]
	}
	return s
}
