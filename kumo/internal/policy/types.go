// Package policy implements the Kumo security policy engine.
//
// Policy evaluation order:
//
//   Request arrives
//       |
//       v
//   Fast rules (linear scan, first match wins)
//       |
//       +---> ALLOW/BLOCK/FLAG → done
//       |
//       v (no match)
//   Judge rules (LLM evaluation, if configured)
//       |
//       +---> ALLOW/BLOCK/FLAG → done
//       |
//       v (no match)
//   Default action (flag or block)
package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Policy is the top-level security policy loaded from YAML.
type Policy struct {
	Version       int    `yaml:"version"`
	Name          string `yaml:"name"`
	Description   string `yaml:"description"`
	GeneratedFrom string `yaml:"generated_from,omitempty"`

	Rules RuleSet   `yaml:"rules"`
	Ban   BanConfig `yaml:"ban"`
}

// RuleSet contains fast rules, judge rules, and a default action.
type RuleSet struct {
	Fast    []FastRule  `yaml:"fast"`
	Judge   []JudgeRule `yaml:"judge"`
	Default string     `yaml:"default"` // "allow", "block", or "flag"
}

// FastRule is a pattern-matching rule with zero LLM cost.
type FastRule struct {
	Name    string    `yaml:"name"`
	Action  string    `yaml:"action"` // "allow", "block", or "flag"
	Match   RuleMatch `yaml:"match"`
	Message string    `yaml:"message,omitempty"`
}

// RuleMatch defines what a fast rule matches against.
type RuleMatch struct {
	Hosts   []string `yaml:"hosts,omitempty"`
	Methods []string `yaml:"methods,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
}

// JudgeRule triggers an LLM evaluation for matching requests.
type JudgeRule struct {
	Name        string    `yaml:"name"`
	Trigger     RuleMatch `yaml:"trigger"`
	Instruction string    `yaml:"instruction"`
	Lookback    int       `yaml:"lookback,omitempty"`
}

// BanConfig controls the ban/rate-limit mechanism.
type BanConfig struct {
	MaxViolations int    `yaml:"max_violations"`
	BanDuration   string `yaml:"ban_duration"` // e.g. "1h"
	Message       string `yaml:"message"`
}

// LoadPolicy reads a policy YAML file from disk.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}

	if p.Rules.Default == "" {
		p.Rules.Default = "flag"
	}

	if p.Ban.MaxViolations == 0 {
		p.Ban.MaxViolations = 3
	}
	if p.Ban.BanDuration == "" {
		p.Ban.BanDuration = "1h"
	}

	return &p, nil
}
