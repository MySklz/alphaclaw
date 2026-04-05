package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":8080")
	}
	if cfg.Judge.OnError != "block" {
		t.Errorf("Judge.OnError = %q, want %q", cfg.Judge.OnError, "block")
	}
	if cfg.Health.Port != 9091 {
		t.Errorf("Health.Port = %d, want %d", cfg.Health.Port, 9091)
	}
}

func TestWriteAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	if err := WriteDefault(path); err != nil {
		t.Fatalf("WriteDefault: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if len(cfg.Agents) != 1 {
		t.Errorf("Agents count = %d, want 1", len(cfg.Agents))
	}
	if cfg.Agents[0].Name != "default-agent" {
		t.Errorf("Agent name = %q", cfg.Agents[0].Name)
	}
}

func TestLoad_Missing(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	os.WriteFile(path, []byte("{{{{not yaml"), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLookupToken(t *testing.T) {
	cfg := &Config{
		Agents: []AgentConfig{
			{Name: "agent1", Token: "tok_a"},
			{Name: "agent2", Token: "tok_b"},
		},
	}

	a := cfg.LookupToken("tok_a")
	if a == nil || a.Name != "agent1" {
		t.Error("failed to find agent1")
	}

	b := cfg.LookupToken("tok_b")
	if b == nil || b.Name != "agent2" {
		t.Error("failed to find agent2")
	}

	c := cfg.LookupToken("tok_unknown")
	if c != nil {
		t.Error("should not find unknown token")
	}
}
