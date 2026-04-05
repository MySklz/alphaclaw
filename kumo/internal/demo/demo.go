// Package demo provides a self-contained demo showing the full Kumo loop
// in ~60 seconds with zero config, zero API key, zero Docker.
//
// It starts a mock upstream server, a Kumo proxy, and a mock agent that
// makes requests through the proxy. Then it generates a policy, switches
// to enforce mode, and shows a blocked request.
package demo

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/kumo-ai/kumo/internal/analyzer"
	"github.com/kumo-ai/kumo/internal/logger"
	"github.com/kumo-ai/kumo/internal/policy"
	"github.com/kumo-ai/kumo/internal/proxy"
)

// Run executes the demo.
func Run() error {
	fmt.Println("=== Kumo Demo ===")
	fmt.Println("Showing the full observe → generate → enforce loop.")
	fmt.Println()

	// Set up temp directory
	dataDir, err := os.MkdirTemp("", "kumo-demo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dataDir)

	// 1. Generate CA
	fmt.Print("1. Generating CA certificate... ")
	caCert, caKey, err := proxy.GenerateCA(dataDir)
	if err != nil {
		return err
	}
	fmt.Println("done")

	// 2. Start mock upstream server
	fmt.Print("2. Starting mock API server... ")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/candidates" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"},{"id":3,"name":"Carol"}]`))
		case r.URL.Path == "/api/candidates/1/notes" && r.Method == "POST":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			w.Write([]byte(`{"status":"created"}`))
		case r.URL.Path == "/api/candidates/1/interviews/1/feedback":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"feedback":"Very strong candidate","rating":5}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	defer upstream.Close()
	fmt.Printf("listening on %s\n", upstream.URL)

	// 3. Start Kumo proxy in observe mode
	fmt.Print("3. Starting Kumo proxy (observe mode)... ")
	logDir := filepath.Join(dataDir, "logs")
	trafficLogger, err := logger.New(logDir)
	if err != nil {
		return err
	}

	handler := proxy.NewHandler(nil, trafficLogger, "observe")
	handler.SetVerbose(true)

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	proxyAddr := listener.Addr().String()
	listener.Close()

	server := proxy.NewServer(proxyAddr, caCert, caKey, handler)
	go server.ListenAndServe()
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("listening on %s\n", proxyAddr)
	fmt.Println()

	// 4. Mock agent makes requests through the proxy
	fmt.Println("4. Agent making requests through Kumo...")
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	requests := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/candidates", ""},
		{"GET", "/api/candidates", ""},
		{"GET", "/api/candidates", ""},
		{"POST", "/api/candidates/1/notes", `{"note":"Strong background in Go"}`},
		{"POST", "/api/candidates/1/notes", `{"note":"Good culture fit"}`},
		{"GET", "/api/candidates/1/interviews/1/feedback", ""},
	}

	for _, r := range requests {
		var body io.Reader
		if r.body != "" {
			body = bytes.NewBufferString(r.body)
		}
		req, _ := http.NewRequest(r.method, upstream.URL+r.path, body)
		if r.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("   ERROR: %v\n", err)
			continue
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	trafficLogger.Flush()
	fmt.Println()

	// 5. Generate policy
	fmt.Println("5. Generating policy from observed traffic...")
	policyPath := filepath.Join(dataDir, "policy.yaml")
	if err := analyzer.Summarize(logDir, policyPath, 200); err != nil {
		return err
	}
	fmt.Println()

	// Read and display the policy
	policyData, _ := os.ReadFile(policyPath)
	fmt.Println("Generated policy:")
	fmt.Println("---")
	fmt.Println(string(policyData))
	fmt.Println("---")

	// 6. Add a block rule for interview feedback
	fmt.Println("6. Adding block rule for interview feedback...")
	pol, _ := policy.LoadPolicy(policyPath)
	blockRule := policy.FastRule{
		Name:   "block_feedback",
		Action: "block",
		Match: policy.RuleMatch{
			Paths: []string{"/api/candidates/*/interviews/*/feedback"},
		},
		Message: "Access to interview feedback is restricted.",
	}
	// Prepend block rule (first-match, so it takes priority)
	pol.Rules.Fast = append([]policy.FastRule{blockRule}, pol.Rules.Fast...)
	policy.SavePolicy(pol, policyPath)
	fmt.Println("   Added: block_feedback (interview feedback access restricted)")
	fmt.Println()

	// 7. Switch to enforce mode
	fmt.Println("7. Switching to enforce mode...")
	engine, _ := policy.NewEngine(pol)
	handler2 := proxy.NewHandler(engine, trafficLogger, "enforce")
	handler2.SetVerbose(true)

	listener2, _ := net.Listen("tcp", "127.0.0.1:0")
	proxyAddr2 := listener2.Addr().String()
	listener2.Close()

	server2 := proxy.NewServer(proxyAddr2, caCert, caKey, handler2)
	go server2.ListenAndServe()
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("   Enforce proxy on %s (%d rules)\n", proxyAddr2, engine.RuleCount())
	fmt.Println()

	// 8. Agent tries the same requests
	fmt.Println("8. Agent making the same requests under enforcement...")
	proxyURL2, _ := url.Parse("http://" + proxyAddr2)
	client2 := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL2),
		},
	}

	for _, r := range requests {
		var body io.Reader
		if r.body != "" {
			body = bytes.NewBufferString(r.body)
		}
		req, _ := http.NewRequest(r.method, upstream.URL+r.path, body)
		if r.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client2.Do(req)
		if err != nil {
			fmt.Printf("   ERROR: %v\n", err)
			continue
		}
		if resp.StatusCode == 403 {
			respBody, _ := io.ReadAll(resp.Body)
			fmt.Printf("   \033[31mBLOCKED\033[0m %s %s → %s\n", r.method, r.path, string(respBody))
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println()
	fmt.Println("=== Demo Complete ===")
	fmt.Println()
	fmt.Println("What just happened:")
	fmt.Println("  1. Kumo observed all agent traffic (6 requests)")
	fmt.Println("  2. Auto-generated a security policy from the traffic")
	fmt.Println("  3. We added a block rule for interview feedback")
	fmt.Println("  4. Switched to enforce mode")
	fmt.Println("  5. The agent's feedback request was BLOCKED")
	fmt.Println()
	fmt.Println("To try with your own agent:")
	fmt.Println("  kumo init")
	fmt.Println("  kumo serve --mode observe --verbose")

	return nil
}

