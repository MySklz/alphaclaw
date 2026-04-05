// Package export generates OpenAPI 3.0 specs from observed traffic.
package export

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/garrytan/kumo/pkg/types"
	"gopkg.in/yaml.v3"
)

type openAPISpec struct {
	OpenAPI string                         `yaml:"openapi"`
	Info    openAPIInfo                    `yaml:"info"`
	Paths   map[string]map[string]pathItem `yaml:"paths"`
}

type openAPIInfo struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description"`
	Version     string `yaml:"version"`
}

type pathItem struct {
	Summary     string              `yaml:"summary"`
	OperationID string              `yaml:"operationId"`
	Responses   map[string]response `yaml:"responses"`
}

type response struct {
	Description string `yaml:"description"`
}

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	numericRe = regexp.MustCompile(`^\d+$`)
	hexRe     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
)

// ExportOpenAPI reads traffic logs and generates an OpenAPI 3.0 spec.
func ExportOpenAPI(logDir, outputPath string) error {
	entries, err := readLogs(logDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("Error: no traffic logs found in %s\nFix: run 'kumo serve --mode observe' first", logDir)
	}

	// Group by host
	hosts := make(map[string][]types.TrafficEntry)
	for _, e := range entries {
		host := e.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		hosts[host] = append(hosts[host], e)
	}

	// Generate one spec per host (or combined)
	spec := &openAPISpec{
		OpenAPI: "3.0.3",
		Info: openAPIInfo{
			Title:       "Agent API Surface",
			Description: fmt.Sprintf("Auto-generated from %d observed requests by Kumo", len(entries)),
			Version:     "1.0.0",
		},
		Paths: make(map[string]map[string]pathItem),
	}

	type pathKey struct {
		template string
		method   string
	}
	seen := make(map[pathKey]int)

	for _, e := range entries {
		template := templatizePath(e.Path)
		key := pathKey{template, strings.ToLower(e.Method)}
		seen[key]++
	}

	// Sort by frequency
	type counted struct {
		key   pathKey
		count int
	}
	var sorted []counted
	for k, v := range seen {
		sorted = append(sorted, counted{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].count > sorted[j].count })

	for _, c := range sorted {
		if spec.Paths[c.key.template] == nil {
			spec.Paths[c.key.template] = make(map[string]pathItem)
		}
		spec.Paths[c.key.template][c.key.method] = pathItem{
			Summary:     fmt.Sprintf("Observed %d times", c.count),
			OperationID: fmt.Sprintf("%s_%s", c.key.method, sanitize(c.key.template)),
			Responses: map[string]response{
				"200": {Description: "Observed successful response"},
			},
		}
	}

	data, err := yaml.Marshal(spec)
	if err != nil {
		return fmt.Errorf("marshal OpenAPI spec: %w", err)
	}

	dir := filepath.Dir(outputPath)
	if dir != "." {
		os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}

	fmt.Printf("OpenAPI spec written to %s (%d paths, %d operations)\n", outputPath, len(spec.Paths), len(sorted))
	return nil
}

func templatizePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if uuidRe.MatchString(part) || numericRe.MatchString(part) || hexRe.MatchString(part) {
			parts[i] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "{", "")
	s = strings.ReplaceAll(s, "}", "")
	s = strings.TrimLeft(s, "_")
	if len(s) > 50 {
		s = s[:50]
	}
	return s
}

func readLogs(dir string) ([]types.TrafficEntry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "traffic-*.jsonl"))
	if err != nil {
		return nil, err
	}
	var entries []types.TrafficEntry
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			var e types.TrafficEntry
			if json.Unmarshal(scanner.Bytes(), &e) == nil {
				entries = append(entries, e)
			}
		}
		file.Close()
	}
	return entries, nil
}
