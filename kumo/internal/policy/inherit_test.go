package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMergePolicies(t *testing.T) {
	base := &Policy{
		Version: 1,
		Name:    "base",
		Rules: RuleSet{
			Fast: []FastRule{
				{Name: "base_block_admin", Action: "block", Match: RuleMatch{Paths: []string{"/admin/**"}}},
				{Name: "base_allow_read", Action: "allow", Match: RuleMatch{Methods: []string{"GET"}}},
			},
			Default: "block",
		},
		Ban: BanConfig{MaxViolations: 5, BanDuration: "2h"},
	}

	override := &Policy{
		Version: 1,
		Name:    "agent-specific",
		Rules: RuleSet{
			Fast: []FastRule{
				{Name: "agent_allow_write", Action: "allow", Match: RuleMatch{
					Hosts:   []string{"api.example.com"},
					Methods: []string{"POST"},
				}},
			},
			Default: "flag",
		},
	}

	merged := MergePolicies(base, override)

	// Override name wins
	if merged.Name != "agent-specific" {
		t.Errorf("Name = %q, want %q", merged.Name, "agent-specific")
	}

	// Override rules come first
	if len(merged.Rules.Fast) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(merged.Rules.Fast))
	}
	if merged.Rules.Fast[0].Name != "agent_allow_write" {
		t.Errorf("first rule = %q, want agent rule first", merged.Rules.Fast[0].Name)
	}
	if merged.Rules.Fast[1].Name != "base_block_admin" {
		t.Errorf("second rule = %q, want base_block_admin", merged.Rules.Fast[1].Name)
	}

	// Override default wins
	if merged.Rules.Default != "flag" {
		t.Errorf("Default = %q, want %q", merged.Rules.Default, "flag")
	}

	// Override ban is zero, so base wins
	if merged.Ban.MaxViolations != 5 {
		t.Errorf("Ban.MaxViolations = %d, want 5", merged.Ban.MaxViolations)
	}
}

func TestMergePolicies_OverrideByName(t *testing.T) {
	base := &Policy{
		Rules: RuleSet{
			Fast: []FastRule{
				{Name: "shared_rule", Action: "block"},
				{Name: "base_only", Action: "allow"},
			},
		},
	}

	override := &Policy{
		Rules: RuleSet{
			Fast: []FastRule{
				{Name: "shared_rule", Action: "allow"}, // overrides base's block
			},
		},
	}

	merged := MergePolicies(base, override)

	if len(merged.Rules.Fast) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(merged.Rules.Fast))
	}

	// shared_rule from override (allow) should be present, not base's (block)
	for _, r := range merged.Rules.Fast {
		if r.Name == "shared_rule" && r.Action != "allow" {
			t.Errorf("shared_rule action = %q, want %q (override should win)", r.Action, "allow")
		}
	}
}

func TestLoadPolicyWithInheritance(t *testing.T) {
	dir := t.TempDir()

	// Write base policy
	basePath := filepath.Join(dir, "base.yaml")
	os.WriteFile(basePath, []byte(`
version: 1
name: base
rules:
  fast:
    - name: block_admin
      action: block
      match:
        paths: ["/admin/**"]
  default: block
`), 0644)

	// Write agent policy
	agentPath := filepath.Join(dir, "agent.yaml")
	os.WriteFile(agentPath, []byte(`
version: 1
name: recruiter
rules:
  fast:
    - name: allow_greenhouse
      action: allow
      match:
        hosts: ["api.greenhouse.io"]
  default: flag
`), 0644)

	pol, err := LoadPolicyWithInheritance(agentPath, basePath)
	if err != nil {
		t.Fatalf("LoadPolicyWithInheritance: %v", err)
	}

	if pol.Name != "recruiter" {
		t.Errorf("Name = %q", pol.Name)
	}
	if len(pol.Rules.Fast) != 2 {
		t.Errorf("expected 2 rules, got %d", len(pol.Rules.Fast))
	}
	// Agent rule first
	if pol.Rules.Fast[0].Name != "allow_greenhouse" {
		t.Errorf("first rule = %q, want allow_greenhouse", pol.Rules.Fast[0].Name)
	}
}

func TestFindBasePolicy(t *testing.T) {
	dir := t.TempDir()

	// No base.yaml
	if got := FindBasePolicy(filepath.Join(dir, "agent.yaml")); got != "" {
		t.Errorf("expected empty, got %q", got)
	}

	// Create base.yaml
	os.WriteFile(filepath.Join(dir, "base.yaml"), []byte("version: 1"), 0644)
	if got := FindBasePolicy(filepath.Join(dir, "agent.yaml")); got == "" {
		t.Error("expected to find base.yaml")
	}
}
