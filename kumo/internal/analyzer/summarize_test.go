package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kumo-ai/kumo/internal/policy"
	"github.com/kumo-ai/kumo/pkg/types"
	"gopkg.in/yaml.v3"
)

func TestExtractPathTemplate(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v1/candidates/123/notes", "/v1/candidates/*/notes"},
		{"/v1/candidates/abc-def/notes", "/v1/candidates/abc-def/notes"}, // not numeric/uuid
		{"/v1/users/550e8400-e29b-41d4-a716-446655440000", "/v1/users/*"},
		{"/v1/items/999999", "/v1/items/*"},
		{"/health", "/health"},
		{"/", "/"},
		{"/v1/commits/abcdef0123456789", "/v1/commits/*"}, // hex 16+ chars
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractPathTemplate(tt.path)
			if got != tt.want {
				t.Errorf("extractPathTemplate(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	os.MkdirAll(logDir, 0755)

	// Write test traffic
	entries := []types.TrafficEntry{
		{Method: "GET", Host: "api.example.com", Path: "/v1/users/123", URL: "https://api.example.com/v1/users/123", Decision: "allow"},
		{Method: "GET", Host: "api.example.com", Path: "/v1/users/456", URL: "https://api.example.com/v1/users/456", Decision: "allow"},
		{Method: "POST", Host: "api.example.com", Path: "/v1/users/123/notes", URL: "https://api.example.com/v1/users/123/notes", Decision: "allow"},
		{Method: "GET", Host: "hooks.slack.com", Path: "/services/T123", URL: "https://hooks.slack.com/services/T123", Decision: "allow"},
	}

	f, _ := os.Create(filepath.Join(logDir, "traffic-2026-04-03.jsonl"))
	for _, e := range entries {
		data, _ := json.Marshal(e)
		f.Write(append(data, '\n'))
	}
	f.Close()

	outputPath := filepath.Join(dir, "policy.yaml")
	err := Summarize(logDir, outputPath, 200)
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}

	// Read and parse the generated policy
	data, _ := os.ReadFile(outputPath)
	var pol policy.Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	if len(pol.Rules.Fast) == 0 {
		t.Error("no fast rules generated")
	}
	if pol.Rules.Default != "flag" {
		t.Errorf("default = %q, want %q", pol.Rules.Default, "flag")
	}
}

func TestSummarize_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "empty-logs")
	os.MkdirAll(logDir, 0755)

	err := Summarize(logDir, filepath.Join(dir, "out.yaml"), 200)
	if err == nil {
		t.Error("expected error for empty log dir")
	}
}
