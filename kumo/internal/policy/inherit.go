package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadPolicyWithInheritance loads a policy and merges it with a base policy
// if the base path is specified. Per-agent rules are appended after base rules
// (first-match means agent-specific rules should come first if they need priority).
func LoadPolicyWithInheritance(agentPolicyPath, basePolicyPath string) (*Policy, error) {
	agent, err := LoadPolicy(agentPolicyPath)
	if err != nil {
		return nil, err
	}

	if basePolicyPath == "" {
		return agent, nil
	}

	base, err := LoadPolicy(basePolicyPath)
	if err != nil {
		return nil, fmt.Errorf("load base policy %s: %w", basePolicyPath, err)
	}

	return MergePolicies(base, agent), nil
}

// MergePolicies combines a base policy with an override policy.
// Override rules come FIRST (higher priority in first-match evaluation).
// Base rules come AFTER. If a rule name exists in both, the override wins.
func MergePolicies(base, override *Policy) *Policy {
	merged := &Policy{
		Version:     override.Version,
		Name:        override.Name,
		Description: override.Description,
	}
	if merged.Name == "" {
		merged.Name = base.Name
	}

	// Build set of override rule names
	overrideNames := make(map[string]bool)
	for _, r := range override.Rules.Fast {
		overrideNames[r.Name] = true
	}

	// Override rules first (higher priority)
	merged.Rules.Fast = append(merged.Rules.Fast, override.Rules.Fast...)

	// Base rules that aren't overridden
	for _, r := range base.Rules.Fast {
		if !overrideNames[r.Name] {
			merged.Rules.Fast = append(merged.Rules.Fast, r)
		}
	}

	// Judge rules: same logic
	overrideJudgeNames := make(map[string]bool)
	for _, r := range override.Rules.Judge {
		overrideJudgeNames[r.Name] = true
	}
	merged.Rules.Judge = append(merged.Rules.Judge, override.Rules.Judge...)
	for _, r := range base.Rules.Judge {
		if !overrideJudgeNames[r.Name] {
			merged.Rules.Judge = append(merged.Rules.Judge, r)
		}
	}

	// Default: override wins, fall back to base
	merged.Rules.Default = override.Rules.Default
	if merged.Rules.Default == "" {
		merged.Rules.Default = base.Rules.Default
	}

	// Ban: override wins, fall back to base
	merged.Ban = override.Ban
	if merged.Ban.MaxViolations == 0 {
		merged.Ban = base.Ban
	}

	return merged
}

// FindBasePolicy looks for a base.yaml in the same directory as the agent policy.
func FindBasePolicy(agentPolicyPath string) string {
	dir := filepath.Dir(agentPolicyPath)
	basePath := filepath.Join(dir, "base.yaml")
	if _, err := os.Stat(basePath); err == nil {
		return basePath
	}
	return ""
}

// SavePolicy writes a policy to disk as YAML.
func SavePolicy(p *Policy, path string) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal policy: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
