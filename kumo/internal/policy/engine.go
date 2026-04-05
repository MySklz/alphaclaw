package policy

import (
	"net/http"
	"strings"

	"github.com/garrytan/kumo/pkg/types"
)

// Engine evaluates requests against a compiled policy.
type Engine struct {
	policy        *Policy
	compiledRules []CompiledFastRule
}

// NewEngine creates a policy engine from a loaded policy.
func NewEngine(p *Policy) (*Engine, error) {
	compiled, err := CompileFastRules(p.Rules.Fast)
	if err != nil {
		return nil, err
	}

	return &Engine{
		policy:        p,
		compiledRules: compiled,
	}, nil
}

// Evaluate checks a request against the policy and returns a decision.
// Evaluation order: fast rules (first match wins) → default action.
// Judge rules are handled separately by the judge package (Phase 3).
func (e *Engine) Evaluate(req *http.Request, token string) types.PolicyDecision {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	method := req.Method
	path := req.URL.Path

	// Fast rules: linear scan, first match wins
	for _, cr := range e.compiledRules {
		if cr.Match(host, method, path) {
			action := parseAction(cr.Rule.Action)
			return types.PolicyDecision{
				Decision: action,
				Rule:     cr.Rule.Name,
				Reason:   "fast_rule:" + cr.Rule.Name,
				Message:  cr.Rule.Message,
			}
		}
	}

	// No fast rule matched, apply default
	defaultAction := parseAction(e.policy.Rules.Default)
	return types.PolicyDecision{
		Decision: defaultAction,
		Reason:   "default:" + e.policy.Rules.Default,
	}
}

// Policy returns the underlying policy.
func (e *Engine) Policy() *Policy {
	return e.policy
}

// RuleCount returns the number of compiled rules.
func (e *Engine) RuleCount() int {
	return len(e.compiledRules)
}

func parseAction(action string) types.Decision {
	switch strings.ToLower(action) {
	case "allow":
		return types.DecisionAllow
	case "block":
		return types.DecisionBlock
	case "flag":
		return types.DecisionFlag
	default:
		return types.DecisionFlag // unknown actions default to flag
	}
}
