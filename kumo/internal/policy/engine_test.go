package policy

import (
	"net/http"
	"testing"

	"github.com/garrytan/kumo/pkg/types"
)

func TestEngineEvaluate(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test-policy",
		Rules: RuleSet{
			Fast: []FastRule{
				{
					Name:   "block_feedback",
					Action: "block",
					Match: RuleMatch{
						Hosts: []string{"api.greenhouse.io"},
						Paths: []string{"/v1/candidates/*/interviews/*/feedback"},
					},
					Message: "Access to interview feedback is restricted.",
				},
				{
					Name:   "allow_greenhouse_read",
					Action: "allow",
					Match: RuleMatch{
						Hosts:   []string{"api.greenhouse.io"},
						Methods: []string{"GET"},
						Paths:   []string{"/v1/candidates/*", "/v1/jobs/*"},
					},
				},
				{
					Name:   "allow_greenhouse_write",
					Action: "allow",
					Match: RuleMatch{
						Hosts:   []string{"api.greenhouse.io"},
						Methods: []string{"POST", "PUT"},
						Paths:   []string{"/v1/candidates/*/notes"},
					},
				},
			},
			Default: "flag",
		},
	}

	engine, err := NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	tests := []struct {
		name     string
		method   string
		host     string
		path     string
		wantDec  types.Decision
		wantRule string
	}{
		{
			name:     "block feedback",
			method:   "GET",
			host:     "api.greenhouse.io",
			path:     "/v1/candidates/123/interviews/456/feedback",
			wantDec:  types.DecisionBlock,
			wantRule: "block_feedback",
		},
		{
			name:     "allow read candidates",
			method:   "GET",
			host:     "api.greenhouse.io",
			path:     "/v1/candidates/123",
			wantDec:  types.DecisionAllow,
			wantRule: "allow_greenhouse_read",
		},
		{
			name:     "allow read jobs",
			method:   "GET",
			host:     "api.greenhouse.io",
			path:     "/v1/jobs/456",
			wantDec:  types.DecisionAllow,
			wantRule: "allow_greenhouse_read",
		},
		{
			name:     "allow write notes",
			method:   "POST",
			host:     "api.greenhouse.io",
			path:     "/v1/candidates/123/notes",
			wantDec:  types.DecisionAllow,
			wantRule: "allow_greenhouse_write",
		},
		{
			name:    "default flag unknown endpoint",
			method:  "GET",
			host:    "api.greenhouse.io",
			path:    "/v1/unknown/endpoint",
			wantDec: types.DecisionFlag,
		},
		{
			name:    "default flag unknown host",
			method:  "GET",
			host:    "api.unknown.com",
			path:    "/anything",
			wantDec: types.DecisionFlag,
		},
		{
			name:    "POST to read-only endpoint defaults to flag",
			method:  "POST",
			host:    "api.greenhouse.io",
			path:    "/v1/candidates/123",
			wantDec: types.DecisionFlag,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "https://"+tt.host+tt.path, nil)
			req.Host = tt.host

			dec := engine.Evaluate(req, "tok_test")

			if dec.Decision != tt.wantDec {
				t.Errorf("decision = %v, want %v", dec.Decision, tt.wantDec)
			}
			if tt.wantRule != "" && dec.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", dec.Rule, tt.wantRule)
			}
		})
	}
}

func TestEngineBlockBeforeAllow(t *testing.T) {
	// Verify that BLOCK rules listed before ALLOW rules take precedence
	// (first-match semantics)
	p := &Policy{
		Version: 1,
		Name:    "precedence-test",
		Rules: RuleSet{
			Fast: []FastRule{
				{
					Name:   "block_sensitive",
					Action: "block",
					Match: RuleMatch{
						Hosts: []string{"api.example.com"},
						Paths: []string{"/admin/**"},
					},
				},
				{
					Name:   "allow_all_example",
					Action: "allow",
					Match: RuleMatch{
						Hosts: []string{"api.example.com"},
					},
				},
			},
			Default: "flag",
		},
	}

	engine, err := NewEngine(p)
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}

	// /admin/users should be BLOCKED (first rule matches)
	req, _ := http.NewRequest("GET", "https://api.example.com/admin/users", nil)
	req.Host = "api.example.com"
	dec := engine.Evaluate(req, "tok_test")
	if dec.Decision != types.DecisionBlock {
		t.Errorf("expected BLOCK for /admin/users, got %v", dec.Decision)
	}

	// /api/data should be ALLOWED (second rule matches)
	req2, _ := http.NewRequest("GET", "https://api.example.com/api/data", nil)
	req2.Host = "api.example.com"
	dec2 := engine.Evaluate(req2, "tok_test")
	if dec2.Decision != types.DecisionAllow {
		t.Errorf("expected ALLOW for /api/data, got %v", dec2.Decision)
	}
}
