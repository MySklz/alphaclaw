package eval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garrytan/kumo/pkg/types"
)

func TestReplay(t *testing.T) {
	dir := t.TempDir()

	// Write a test policy
	policyContent := `
version: 1
name: test-policy
rules:
  fast:
    - name: allow_read
      action: allow
      match:
        hosts: ["api.example.com"]
        methods: ["GET"]
    - name: block_delete
      action: block
      match:
        methods: ["DELETE"]
  default: flag
`
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte(policyContent), 0644)

	// Write test traffic log
	entries := []types.TrafficEntry{
		{Method: "GET", Host: "api.example.com", Path: "/users", URL: "https://api.example.com/users", Decision: "allow"},
		{Method: "DELETE", Host: "api.example.com", Path: "/users/1", URL: "https://api.example.com/users/1", Decision: "allow"}, // was allowed, should be blocked
		{Method: "POST", Host: "api.unknown.com", Path: "/data", URL: "https://api.unknown.com/data", Decision: "allow"},          // was allowed, should be flagged
	}

	logPath := filepath.Join(dir, "traffic.jsonl")
	f, _ := os.Create(logPath)
	for _, e := range entries {
		data, _ := json.Marshal(e)
		f.Write(append(data, '\n'))
	}
	f.Close()

	summary, err := Replay(logPath, policyPath)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if summary.TotalRequests != 3 {
		t.Errorf("TotalRequests = %d, want 3", summary.TotalRequests)
	}
	if summary.Passed != 1 {
		t.Errorf("Passed = %d, want 1", summary.Passed)
	}
	if summary.Failed != 2 {
		t.Errorf("Failed = %d, want 2", summary.Failed)
	}
	if summary.WouldBlock != 1 {
		t.Errorf("WouldBlock = %d, want 1", summary.WouldBlock)
	}
}

func TestReplay_MissingPolicy(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "traffic.jsonl")
	os.WriteFile(logPath, []byte(`{"method":"GET"}`), 0644)

	_, err := Replay(logPath, "/nonexistent/policy.yaml")
	if err == nil {
		t.Error("expected error for missing policy")
	}
}

func TestReplay_EmptyLog(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyPath, []byte("version: 1\nrules:\n  default: flag\n"), 0644)
	logPath := filepath.Join(dir, "empty.jsonl")
	os.WriteFile(logPath, []byte(""), 0644)

	_, err := Replay(logPath, policyPath)
	if err == nil {
		t.Error("expected error for empty log")
	}
}

func TestWriteReport(t *testing.T) {
	dir := t.TempDir()
	summary := &ReplaySummary{
		TotalRequests: 10,
		Passed:        8,
		Failed:        2,
		WouldBlock:    1,
		Flagged:       1,
	}

	reportPath := filepath.Join(dir, "reports", "eval.md")
	err := WriteReport(summary, reportPath)
	if err != nil {
		t.Fatalf("WriteReport: %v", err)
	}

	data, _ := os.ReadFile(reportPath)
	if len(data) == 0 {
		t.Error("report is empty")
	}
}
