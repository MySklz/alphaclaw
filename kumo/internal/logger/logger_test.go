package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/garrytan/kumo/pkg/types"
)

func TestLoggerWritesJSONL(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	entry := types.TrafficEntry{
		ID:        "req_test_1",
		Timestamp: time.Now(),
		Method:    "GET",
		URL:       "https://example.com/test",
		Host:      "example.com",
		Path:      "/test",
		Decision:  "allow",
	}

	l.Log(entry)
	l.Flush()

	// Find the log file
	files, _ := filepath.Glob(filepath.Join(dir, "traffic-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no log files created")
	}

	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var parsed types.TrafficEntry
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.ID != "req_test_1" {
		t.Errorf("ID = %q, want %q", parsed.ID, "req_test_1")
	}
	if parsed.Method != "GET" {
		t.Errorf("Method = %q, want %q", parsed.Method, "GET")
	}
}

func TestLoggerMultipleEntries(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 50; i++ {
		l.Log(types.TrafficEntry{
			ID:       "req_" + string(rune('A'+i%26)),
			Method:   "GET",
			Decision: "allow",
		})
	}
	l.Flush()

	files, _ := filepath.Glob(filepath.Join(dir, "traffic-*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no log files")
	}

	data, _ := os.ReadFile(files[0])
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("expected 50 lines, got %d", len(lines))
	}
}

func TestLoggerCreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "logs")
	l, err := New(dir)
	if err != nil {
		t.Fatalf("New with nested dir: %v", err)
	}
	l.Log(types.TrafficEntry{ID: "test"})
	l.Flush()

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("directory not created: %v", err)
	}
}
