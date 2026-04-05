package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/kumo-ai/kumo/pkg/types"
)

// PolicyEngine evaluates requests against security policies.
type PolicyEngine interface {
	Evaluate(req *http.Request, token string) types.PolicyDecision
}

// TrafficLogger logs traffic entries.
type TrafficLogger interface {
	Log(entry types.TrafficEntry)
}

// BanChecker checks if an agent is banned and records violations.
type BanChecker interface {
	IsBanned(token string) bool
	RecordViolation(token, rule string) (violations int, banned bool)
	MaxViolations() int
	BanMessage() string
}

// Notifier sends events on block/flag/ban.
type Notifier interface {
	Notify(ctx context.Context, event types.NotifyEvent) error
}

// Handler processes intercepted HTTP requests.
type Handler struct {
	engine   PolicyEngine
	logger   TrafficLogger
	bans     BanChecker
	notifier Notifier
	mode     string // "observe" or "enforce"
	verbose  bool

	mu         sync.Mutex
	pendingReq map[uint64]*pendingRequest
	nextID     uint64
}

type pendingRequest struct {
	entry types.TrafficEntry
	start time.Time
}

// NewHandler creates a new request handler.
func NewHandler(engine PolicyEngine, logger TrafficLogger, mode string) *Handler {
	return &Handler{
		engine:     engine,
		logger:     logger,
		mode:       mode,
		pendingReq: make(map[uint64]*pendingRequest),
	}
}

// SetBanChecker sets the ban manager.
func (h *Handler) SetBanChecker(b BanChecker) { h.bans = b }

// SetNotifier sets the webhook notifier.
func (h *Handler) SetNotifier(n Notifier) { h.notifier = n }

// SetVerbose enables per-request logging to stdout.
func (h *Handler) SetVerbose(v bool) {
	h.verbose = v
}

// HandleRequest is called for every intercepted request.
func (h *Handler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	start := time.Now()

	// Extract proxy auth token
	token := extractProxyAuth(req)

	// Strip Proxy-Authorization before forwarding (never leak upstream)
	req.Header.Del("Proxy-Authorization")

	// In enforce mode, require auth
	if h.mode == "enforce" && token == "" {
		return req, ProxyAuthRequired(req)
	}

	if token == "" {
		token = "anonymous"
	}

	// Check ban before evaluating policy
	if h.mode == "enforce" && h.bans != nil && h.bans.IsBanned(token) {
		return req, BannedResponse(req, h.bans.BanMessage())
	}

	// Evaluate policy (skip in observe mode)
	var decision types.PolicyDecision
	if h.mode == "enforce" && h.engine != nil {
		decision = h.engine.Evaluate(req, token)
	} else {
		decision = types.PolicyDecision{
			Decision: types.DecisionAllow,
			Reason:   "observe_mode",
		}
	}

	// Read request body for logging (tee-read pattern)
	bodySample, bodyHash, bodySize := readRequestBody(req)

	// Build traffic entry
	entry := types.TrafficEntry{
		ID:                generateRequestID(),
		Timestamp:         time.Now(),
		Method:            req.Method,
		URL:               req.URL.String(),
		Host:              req.URL.Host,
		Path:              req.URL.Path,
		RequestHeaders:    redactHeaders(req.Header),
		RequestBodyHash:   bodyHash,
		RequestBodySize:   bodySize,
		RequestBodySample: bodySample,
		Decision:          decision.Decision.String(),
		DecisionReason:    decision.Reason,
		GatewayToken:      token,
	}

	if h.verbose {
		fmt.Printf("[%s] %s %s%s (%s)\n",
			colorDecision(decision.Decision), req.Method, req.URL.Host, req.URL.Path, decision.Reason)
	}

	// Block if policy says so
	if decision.Decision == types.DecisionBlock {
		violations := 1
		maxV := 3
		if h.bans != nil {
			v, _ := h.bans.RecordViolation(token, decision.Rule)
			violations = v
			maxV = h.bans.MaxViolations()
		}
		h.logger.Log(entry)

		// Fire notification
		if h.notifier != nil {
			go h.notifier.Notify(context.Background(), types.NotifyEvent{
				Type:       "block",
				AgentName:  token,
				Token:      token,
				Rule:       decision.Rule,
				Method:     req.Method,
				URL:        req.URL.String(),
				Message:    decision.Message,
				Violations: violations,
				Timestamp:  time.Now(),
			})
		}

		return req, BlockedResponse(req, decision.Rule, decision.Message, violations, maxV)
	}

	// Fire notification for flagged requests
	if decision.Decision == types.DecisionFlag && h.notifier != nil {
		go h.notifier.Notify(context.Background(), types.NotifyEvent{
			Type:      "flag",
			AgentName: token,
			Token:     token,
			Rule:      decision.Rule,
			Method:    req.Method,
			URL:       req.URL.String(),
			Timestamp: time.Now(),
		})
	}

	// Store entry for response handler via goproxy's UserData
	h.mu.Lock()
	id := h.nextID
	h.nextID++
	h.pendingReq[id] = &pendingRequest{entry: entry, start: start}
	h.mu.Unlock()
	ctx.UserData = id

	return req, nil
}

// HandleResponse is called for every response (after upstream returns).
func (h *Handler) HandleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || ctx.UserData == nil {
		return resp
	}

	id, ok := ctx.UserData.(uint64)
	if !ok {
		return resp
	}

	h.mu.Lock()
	pending, exists := h.pendingReq[id]
	if exists {
		delete(h.pendingReq, id)
	}
	h.mu.Unlock()

	if !exists {
		return resp
	}

	// Complete the entry with response data
	pending.entry.ResponseStatus = resp.StatusCode
	if resp.ContentLength >= 0 {
		pending.entry.ResponseBodySize = resp.ContentLength
	}
	pending.entry.DurationMs = time.Since(pending.start).Milliseconds()

	h.logger.Log(pending.entry)
	return resp
}

// extractProxyAuth extracts the username from Proxy-Authorization Basic auth.
func extractProxyAuth(req *http.Request) string {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return ""
	}
	if !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// readRequestBody reads up to 10KB for logging and reconstructs the body for forwarding.
func readRequestBody(req *http.Request) (sample string, hash string, size int64) {
	if req.Body == nil {
		return "", "", 0
	}

	ct := req.Header.Get("Content-Type")
	loggable := strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/x-www-form-urlencoded") ||
		strings.Contains(ct, "text/")

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(nil))
		return "", "", 0
	}
	req.Body.Close()

	// Reconstruct the body for forwarding
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))

	// Hash
	h := sha256.Sum256(bodyBytes)
	hash = fmt.Sprintf("sha256:%x", h[:])
	size = int64(len(bodyBytes))

	// Sample (only for loggable content types, max 10KB)
	if loggable && len(bodyBytes) > 0 {
		limit := 10240
		if len(bodyBytes) < limit {
			limit = len(bodyBytes)
		}
		sample = string(bodyBytes[:limit])
	}

	return sample, hash, size
}

// redactHeaders copies headers, redacting sensitive values.
func redactHeaders(headers http.Header) map[string]string {
	redacted := make(map[string]string)
	sensitive := map[string]bool{
		"authorization":       true,
		"cookie":              true,
		"x-api-key":           true,
		"proxy-authorization": true,
	}
	for key, vals := range headers {
		if sensitive[strings.ToLower(key)] {
			redacted[key] = "[REDACTED]"
		} else if len(vals) > 0 {
			redacted[key] = vals[0]
		}
	}
	return redacted
}

var (
	reqCounterMu sync.Mutex
	reqCounter   uint64
)

func generateRequestID() string {
	reqCounterMu.Lock()
	reqCounter++
	id := reqCounter
	reqCounterMu.Unlock()
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), id)
}

func colorDecision(d types.Decision) string {
	switch d {
	case types.DecisionAllow:
		return "\033[32mALLOW\033[0m" // green
	case types.DecisionBlock:
		return "\033[31mBLOCK\033[0m" // red
	case types.DecisionFlag:
		return "\033[33mFLAG\033[0m" // yellow
	default:
		return d.String()
	}
}
