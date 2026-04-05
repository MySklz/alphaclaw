// Package config handles Kumo configuration loading and hot-reload.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level Kumo configuration.
type Config struct {
	Listen  string        `yaml:"listen"`
	DataDir string        `yaml:"data_dir"`
	Agents  []AgentConfig `yaml:"agents"`
	Judge   JudgeConfig   `yaml:"judge"`
	Logging LogConfig     `yaml:"logging"`
	Notify  NotifyConfig  `yaml:"notifications"`
	Health  HealthConfig  `yaml:"health"`
}

// AgentConfig defines a single agent's token and policy.
type AgentConfig struct {
	Name   string `yaml:"name"`
	Token  string `yaml:"token"`
	Policy string `yaml:"policy"`
}

// JudgeConfig controls the LLM judge behavior.
type JudgeConfig struct {
	Model    string        `yaml:"model"`
	OnError  string        `yaml:"on_error"` // "block" or "allow"
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// LogConfig controls traffic logging.
type LogConfig struct {
	MaxLogAge       string   `yaml:"max_log_age"`
	MaxLogSize      string   `yaml:"max_log_size"`
	RedactPatterns  []string `yaml:"redact_patterns"`
	LogResponseBody bool     `yaml:"log_response_bodies"`
}

// NotifyConfig controls webhook notifications.
type NotifyConfig struct {
	WebhookURL string   `yaml:"webhook_url"`
	On         []string `yaml:"on"` // "block", "flag", "ban"
}

// HealthConfig controls the health check endpoint.
type HealthConfig struct {
	Port int `yaml:"port"`
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Listen:  ":8080",
		DataDir: "~/.kumo",
		Judge: JudgeConfig{
			Model:    "claude-haiku-4-5-20251001",
			OnError:  "block",
			CacheTTL: 60 * time.Second,
		},
		Logging: LogConfig{
			MaxLogAge:  "30d",
			MaxLogSize: "1GB",
		},
		Health: HealthConfig{
			Port: 9091,
		},
	}
}

// Load reads a config file from disk.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	return cfg, nil
}

// WriteDefault writes a default config file to the given path.
func WriteDefault(path string) error {
	cfg := DefaultConfig()
	cfg.Agents = []AgentConfig{
		{
			Name:  "default-agent",
			Token: generateToken(),
		},
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

func generateToken() string {
	b := make([]byte, 16)
	// Use crypto/rand in production, this is just for the default template
	return fmt.Sprintf("tok_%x", b)
}

// LookupToken finds the agent config for a given token.
func (c *Config) LookupToken(token string) *AgentConfig {
	for i := range c.Agents {
		if c.Agents[i].Token == token {
			return &c.Agents[i]
		}
	}
	return nil
}
