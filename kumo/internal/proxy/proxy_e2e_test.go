package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kumo-ai/kumo/internal/logger"
	"github.com/kumo-ai/kumo/internal/policy"
	"github.com/kumo-ai/kumo/internal/proxy"
	"github.com/kumo-ai/kumo/pkg/types"
)

// testHarness holds all the components for an e2e test.
type testHarness struct {
	ProxyURL  string
	Upstream  *httptest.Server
	LogDir    string
	Logger    *logger.Logger
	CACert    *x509.Certificate
	ProxyTS   *httptest.Server
	HitCount  *atomic.Int32
}

func (h *testHarness) Close() {
	h.Logger.Flush()
	h.ProxyTS.Close()
	h.Upstream.Close()
}

// makeClient creates an HTTP client configured to use the proxy and trust the CA.
func (h *testHarness) makeClient(token string) *http.Client {
	caPool := x509.NewCertPool()
	caPool.AddCert(h.CACert)
	proxyURL, _ := url.Parse(h.ProxyURL)

	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}

	return &http.Client{
		Transport: &proxyAuthTransport{token: token, base: tr},
	}
}

// proxyAuthTransport adds Proxy-Authorization to every request.
type proxyAuthTransport struct {
	token string
	base  http.RoundTripper
}

func (t *proxyAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(t.token + ":"))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	return t.base.RoundTrip(req)
}

// setupE2E creates a full e2e harness: upstream + proxy + logger.
func setupE2E(t *testing.T, mode string, pol *policy.Policy) *testHarness {
	t.Helper()
	dataDir := t.TempDir()

	// Generate CA
	caCert, caKey, err := proxy.GenerateCA(dataDir)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	// Upstream: tracks hit count
	var hitCount atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))

	// Logger (fresh per test to avoid Flush panic)
	logDir := filepath.Join(dataDir, "logs")
	trafficLogger, err := logger.New(logDir)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}

	// Policy engine
	var engine proxy.PolicyEngine
	if mode == "enforce" && pol != nil {
		eng, err := policy.NewEngine(pol)
		if err != nil {
			t.Fatalf("NewEngine: %v", err)
		}
		engine = eng
	}

	handler := proxy.NewHandler(engine, trafficLogger, mode)

	// Ban manager
	if mode == "enforce" && pol != nil {
		banMgr := policy.NewBanManager(pol.Ban)
		handler.SetBanChecker(banMgr)
	}

	// Start proxy via httptest.NewServer
	server := proxy.NewServer(":0", caCert, caKey, handler)
	server.SetTransport(&http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	ts := httptest.NewServer(server)

	return &testHarness{
		ProxyURL:  ts.URL,
		Upstream:  upstream,
		LogDir:    logDir,
		Logger:    trafficLogger,
		CACert:    caCert,
		ProxyTS:   ts,
		HitCount:  &hitCount,
	}
}

// readLogEntries reads all JSONL log entries from the log directory.
func readLogEntries(t *testing.T, logDir string) []types.TrafficEntry {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(logDir, "traffic-*.jsonl"))
	var entries []types.TrafficEntry
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read log file %s: %v", path, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var entry types.TrafficEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("unmarshal log entry: %v", err)
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

// testPolicy creates a policy for enforce mode tests.
func testPolicy() *policy.Policy {
	return &policy.Policy{
		Version: 1,
		Name:    "test-policy",
		Rules: policy.RuleSet{
			Fast: []policy.FastRule{
				{
					Name:   "allow_get",
					Action: "allow",
					Match:  policy.RuleMatch{Methods: []string{"GET"}, Paths: []string{"/api/**"}},
				},
				{
					Name:    "block_delete",
					Action:  "block",
					Match:   policy.RuleMatch{Methods: []string{"DELETE"}, Paths: []string{"/api/**"}},
					Message: "DELETE operations are not permitted.",
				},
			},
			Default: "flag",
		},
		Ban: policy.BanConfig{
			MaxViolations: 2,
			BanDuration:   "1h",
			Message:       "Agent suspended for repeated violations.",
		},
	}
}

func TestE2E_ObserveMode_HTTP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := setupE2E(t, "observe", nil)
	defer h.Close()

	client := h.makeClient("")
	resp, err := client.Get(h.Upstream.URL + "/api/candidates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if h.HitCount.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1", h.HitCount.Load())
	}

	// Flush and verify log
	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond) // let writeLoop drain

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries found")
	}
	if entries[0].Decision != "allow" {
		t.Errorf("decision = %q, want %q", entries[0].Decision, "allow")
	}
	if entries[0].DecisionReason != "observe_mode" {
		t.Errorf("decision_reason = %q, want %q", entries[0].DecisionReason, "observe_mode")
	}
}

func TestE2E_ObserveMode_HTTPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := setupE2E(t, "observe", nil)
	defer h.Close()

	// Create HTTPS upstream
	httpsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HitCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tls":"ok"}`))
	}))
	defer httpsUpstream.Close()

	client := h.makeClient("")
	resp, err := client.Get(httpsUpstream.URL + "/api/secure")
	if err != nil {
		t.Fatalf("GET HTTPS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond)

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries found for HTTPS request")
	}
	if entries[0].Decision != "allow" {
		t.Errorf("decision = %q, want %q", entries[0].Decision, "allow")
	}
	if !strings.Contains(entries[0].Path, "/api/secure") {
		t.Errorf("path = %q, want to contain /api/secure", entries[0].Path)
	}
}

func TestE2E_EnforceMode_Allow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	pol := testPolicy()
	h := setupE2E(t, "enforce", pol)
	defer h.Close()

	client := h.makeClient("tok_agent")
	resp, err := client.Get(h.Upstream.URL + "/api/candidates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if h.HitCount.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1", h.HitCount.Load())
	}

	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond)

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries")
	}
	if entries[0].Decision != "allow" {
		t.Errorf("decision = %q, want %q", entries[0].Decision, "allow")
	}
}

func TestE2E_EnforceMode_Block(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	pol := testPolicy()
	h := setupE2E(t, "enforce", pol)
	defer h.Close()

	client := h.makeClient("tok_agent")
	req, _ := http.NewRequest("DELETE", h.Upstream.URL+"/api/candidates/1", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "blocked_by_policy") {
		t.Errorf("body = %q, want to contain 'blocked_by_policy'", body)
	}

	if h.HitCount.Load() != 0 {
		t.Errorf("upstream hits = %d, want 0 (blocked request should not reach upstream)", h.HitCount.Load())
	}

	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond)

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries")
	}
	if entries[0].Decision != "block" {
		t.Errorf("decision = %q, want %q", entries[0].Decision, "block")
	}
}

func TestE2E_EnforceMode_Flag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	pol := testPolicy()
	h := setupE2E(t, "enforce", pol)
	defer h.Close()

	// POST to a path that matches no fast rule -> falls to default "flag"
	client := h.makeClient("tok_agent")
	req, _ := http.NewRequest("POST", h.Upstream.URL+"/unknown/path", strings.NewReader(`{"test":true}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	// Flagged requests are forwarded (not blocked)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200 (flagged requests are forwarded)", resp.StatusCode)
	}
	if h.HitCount.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1", h.HitCount.Load())
	}

	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond)

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries")
	}
	if entries[0].Decision != "flag" {
		t.Errorf("decision = %q, want %q", entries[0].Decision, "flag")
	}
}

func TestE2E_EnforceMode_ProxyAuthRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	pol := testPolicy()
	h := setupE2E(t, "enforce", pol)
	defer h.Close()

	// No proxy auth token
	client := h.makeClient("")
	resp, err := client.Get(h.Upstream.URL + "/api/candidates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 407 {
		t.Errorf("status = %d, want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") != `Basic realm="Kumo"` {
		t.Errorf("Proxy-Authenticate = %q, want Basic realm=\"Kumo\"", resp.Header.Get("Proxy-Authenticate"))
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "proxy_auth_required") {
		t.Errorf("body should contain proxy_auth_required")
	}
	// Verify the help message for agents
	if !strings.Contains(string(body), "INSTALL.md") {
		t.Errorf("407 body should reference INSTALL.md for agent resolver pattern")
	}

	if h.HitCount.Load() != 0 {
		t.Errorf("upstream hits = %d, want 0", h.HitCount.Load())
	}
}

func TestE2E_EnforceMode_Ban(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	pol := testPolicy()
	pol.Ban.MaxViolations = 2
	h := setupE2E(t, "enforce", pol)
	defer h.Close()

	client := h.makeClient("tok_bad_agent")

	// Trigger 2 violations (max_violations = 2, so 2nd triggers ban)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("DELETE", h.Upstream.URL+"/api/candidates/1", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("DELETE #%d: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("DELETE #%d: status = %d, want 403", i+1, resp.StatusCode)
		}
	}

	// 3rd request should be banned (429)
	req, _ := http.NewRequest("GET", h.Upstream.URL+"/api/candidates", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET after ban: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 429 {
		t.Errorf("status = %d, want 429 (agent should be banned)", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "agent_banned") {
		t.Errorf("body = %q, want to contain 'agent_banned'", body)
	}
}

func TestE2E_EnforceMode_BanIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	pol := testPolicy()
	pol.Ban.MaxViolations = 2
	h := setupE2E(t, "enforce", pol)
	defer h.Close()

	// Ban tok_a
	clientA := h.makeClient("tok_a")
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("DELETE", h.Upstream.URL+"/api/candidates/1", nil)
		resp, _ := clientA.Do(req)
		resp.Body.Close()
	}

	// Verify tok_a is banned
	req, _ := http.NewRequest("GET", h.Upstream.URL+"/api/candidates", nil)
	resp, _ := clientA.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Errorf("tok_a: status = %d, want 429 (should be banned)", resp.StatusCode)
	}

	// Verify tok_b is NOT banned
	clientB := h.makeClient("tok_b")
	req2, _ := http.NewRequest("GET", h.Upstream.URL+"/api/candidates", nil)
	resp2, err := clientB.Do(req2)
	if err != nil {
		t.Fatalf("tok_b GET: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Errorf("tok_b: status = %d, want 200 (should not be banned)", resp2.StatusCode)
	}
}

func TestE2E_BodyForwarding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := setupE2E(t, "observe", nil)
	// Replace upstream to capture body
	h.Upstream.Close()
	var receivedBody string
	h.Upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HitCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer h.Close()

	client := h.makeClient("")
	bodyStr := `{"name":"Alice","role":"engineer"}`
	req, _ := http.NewRequest("POST", h.Upstream.URL+"/api/candidates", strings.NewReader(bodyStr))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()

	if receivedBody != bodyStr {
		t.Errorf("upstream received body = %q, want %q", receivedBody, bodyStr)
	}

	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond)

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries")
	}
	if entries[0].RequestBodySample != bodyStr {
		t.Errorf("log body sample = %q, want %q", entries[0].RequestBodySample, bodyStr)
	}
	if entries[0].RequestBodyHash == "" {
		t.Error("log body hash should not be empty")
	}
}

func TestE2E_HeaderRedaction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}

	h := setupE2E(t, "observe", nil)
	// Replace upstream to capture headers
	h.Upstream.Close()
	var gotAuth string
	var gotProxyAuth string
	h.Upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HitCount.Add(1)
		gotAuth = r.Header.Get("Authorization")
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer h.Close()

	client := h.makeClient("")
	req, _ := http.NewRequest("GET", h.Upstream.URL+"/api/data", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	// Authorization IS forwarded to upstream (Kumo only redacts in logs)
	if gotAuth != "Bearer secret-token-123" {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, "Bearer secret-token-123")
	}

	// Proxy-Authorization is stripped before upstream (handler.go:89-90)
	if gotProxyAuth != "" {
		t.Errorf("upstream Proxy-Authorization = %q, want empty (should be stripped)", gotProxyAuth)
	}

	h.Logger.Flush()
	time.Sleep(50 * time.Millisecond)

	entries := readLogEntries(t, h.LogDir)
	if len(entries) == 0 {
		t.Fatal("no log entries")
	}

	// In logs, Authorization should be redacted
	if entries[0].RequestHeaders["Authorization"] != "[REDACTED]" {
		t.Errorf("logged Authorization = %q, want [REDACTED]", entries[0].RequestHeaders["Authorization"])
	}
}
