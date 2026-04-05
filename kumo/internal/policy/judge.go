// Package policy contains the LLM judge for evaluating ambiguous requests.
//
// The judge fires only when a request matches a JudgeRule trigger but no
// FastRule matched first. It sends the request details + lookback context
// to Claude Haiku and gets an allow/block/flag decision with reasoning.
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// LookbackEntry is a condensed record of a recent request for context.
type LookbackEntry struct {
	Timestamp time.Time `json:"ts"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	Decision  string    `json:"decision"`
}

// RingBuffer stores recent request summaries per agent token.
type RingBuffer struct {
	mu      sync.Mutex
	entries []LookbackEntry
	maxSize int
}

// NewRingBuffer creates a ring buffer with the given max size.
func NewRingBuffer(maxSize int) *RingBuffer {
	if maxSize <= 0 {
		maxSize = 200
	}
	return &RingBuffer{
		entries: make([]LookbackEntry, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add appends an entry, evicting the oldest if at capacity.
func (rb *RingBuffer) Add(entry LookbackEntry) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.entries) >= rb.maxSize {
		rb.entries = rb.entries[1:]
	}
	rb.entries = append(rb.entries, entry)
}

// Last returns the last N entries.
func (rb *RingBuffer) Last(n int) []LookbackEntry {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if n > len(rb.entries) {
		n = len(rb.entries)
	}
	result := make([]LookbackEntry, n)
	copy(result, rb.entries[len(rb.entries)-n:])
	return result
}

// LookbackManager maintains per-token ring buffers.
type LookbackManager struct {
	mu      sync.RWMutex
	buffers map[string]*RingBuffer
	maxSize int
}

// NewLookbackManager creates a manager with the given per-token buffer size.
func NewLookbackManager(maxSize int) *LookbackManager {
	return &LookbackManager{
		buffers: make(map[string]*RingBuffer),
		maxSize: maxSize,
	}
}

// Record adds an entry to the token's ring buffer.
func (lm *LookbackManager) Record(token string, entry LookbackEntry) {
	lm.mu.RLock()
	rb, ok := lm.buffers[token]
	lm.mu.RUnlock()

	if !ok {
		lm.mu.Lock()
		rb, ok = lm.buffers[token]
		if !ok {
			rb = NewRingBuffer(lm.maxSize)
			lm.buffers[token] = rb
		}
		lm.mu.Unlock()
	}

	rb.Add(entry)
}

// GetLookback retrieves the last N entries for a token.
func (lm *LookbackManager) GetLookback(token string, n int) []LookbackEntry {
	lm.mu.RLock()
	rb, ok := lm.buffers[token]
	lm.mu.RUnlock()

	if !ok {
		return nil
	}
	return rb.Last(n)
}

// JudgeRequest is the input to the LLM judge.
type JudgeRequest struct {
	Method      string
	URL         string
	Host        string
	Path        string
	Headers     map[string]string
	BodySample  string
	Token       string
	Rule        JudgeRule
	Lookback    []LookbackEntry
}

// JudgeResult is the LLM judge's decision.
type JudgeResult struct {
	Decision  string `json:"decision"` // "allow", "block", "flag"
	Reasoning string `json:"reasoning"`
}

// JudgeClient calls the LLM to evaluate a request.
type JudgeClient interface {
	Judge(ctx context.Context, req JudgeRequest) (JudgeResult, error)
}

// StubJudgeClient always returns flag (placeholder until Anthropic SDK is wired).
type StubJudgeClient struct{}

// Judge returns a flag decision with a note that the real judge isn't configured.
func (s *StubJudgeClient) Judge(ctx context.Context, req JudgeRequest) (JudgeResult, error) {
	return JudgeResult{
		Decision:  "flag",
		Reasoning: "LLM judge not configured. Flagging for manual review.",
	}, nil
}

// FormatLookback formats lookback entries as a string for LLM context.
func FormatLookback(entries []LookbackEntry) string {
	if len(entries) == 0 {
		return "No recent traffic history."
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Recent %d requests from this agent:\n", len(entries)))
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("  %s %s %s%s → %d (%s)\n",
			e.Timestamp.Format("15:04:05"), e.Method, e.Host, e.Path, e.Status, e.Decision))
	}
	return b.String()
}
