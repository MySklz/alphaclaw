// Package types defines shared types used across Kumo packages.
package types

import "time"

// Decision represents the outcome of a policy evaluation.
type Decision int

const (
	DecisionAllow Decision = iota
	DecisionBlock
	DecisionFlag
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionBlock:
		return "block"
	case DecisionFlag:
		return "flag"
	default:
		return "unknown"
	}
}

// TrafficEntry is a single logged request/response pair.
type TrafficEntry struct {
	ID                string            `json:"id"`
	Timestamp         time.Time         `json:"ts"`
	SessionID         string            `json:"session_id,omitempty"`
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Host              string            `json:"host"`
	Path              string            `json:"path"`
	PathTemplate      string            `json:"path_template,omitempty"`
	RequestHeaders    map[string]string `json:"request_headers,omitempty"`
	RequestBodyHash    string            `json:"request_body_hash,omitempty"`
	RequestBodySize    int64             `json:"request_body_size"`
	RequestBodySample  string            `json:"request_body_sample,omitempty"`
	BodyHashPartial    bool              `json:"body_hash_partial,omitempty"`
	ResponseStatus    int               `json:"response_status"`
	ResponseBodySize  int64             `json:"response_body_size"`
	DurationMs        int64             `json:"duration_ms"`
	Decision          string            `json:"decision"`
	DecisionReason    string            `json:"decision_reason,omitempty"`
	GatewayToken      string            `json:"gateway_token,omitempty"`
}

// PolicyDecision is the result of evaluating a request against the policy engine.
type PolicyDecision struct {
	Decision Decision
	Rule     string
	Reason   string
	Message  string // message to return to the agent on BLOCK
}

// NotifyEvent is sent to webhook endpoints on block/flag.
type NotifyEvent struct {
	Type       string    `json:"type"` // "block", "flag", "ban"
	AgentName  string    `json:"agent_name"`
	Token      string    `json:"token"`
	Rule       string    `json:"rule"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	Message    string    `json:"message,omitempty"`
	Violations int       `json:"violations,omitempty"`
	Timestamp  time.Time `json:"ts"`
}
