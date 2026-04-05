package proxy

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/kumo-ai/kumo/pkg/types"
)

func TestExtractProxyAuth(t *testing.T) {
	tests := []struct {
		name  string
		auth  string
		want  string
	}{
		{"no header", "", ""},
		{"basic with password", "Basic " + base64.StdEncoding.EncodeToString([]byte("tok_jim:")), "tok_jim"},
		{"basic no password", "Basic " + base64.StdEncoding.EncodeToString([]byte("tok_jim")), "tok_jim"},
		{"not basic", "Bearer xyz", ""},
		{"invalid base64", "Basic !!!invalid!!!", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			if tt.auth != "" {
				req.Header.Set("Proxy-Authorization", tt.auth)
			}
			got := extractProxyAuth(req)
			if got != tt.want {
				t.Errorf("extractProxyAuth() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadRequestBody(t *testing.T) {
	t.Run("nil body", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		sample, hash, size := readRequestBody(req)
		if sample != "" || hash != "" || size != 0 {
			t.Errorf("nil body: sample=%q hash=%q size=%d", sample, hash, size)
		}
	})

	t.Run("json body", func(t *testing.T) {
		body := `{"name":"test"}`
		req, _ := http.NewRequest("POST", "http://example.com", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		sample, hash, size := readRequestBody(req)
		if sample != body {
			t.Errorf("sample = %q, want %q", sample, body)
		}
		if hash == "" {
			t.Error("hash should not be empty")
		}
		if size != int64(len(body)) {
			t.Errorf("size = %d, want %d", size, len(body))
		}

		// Body should still be readable after tee-read
		buf := new(bytes.Buffer)
		buf.ReadFrom(req.Body)
		if buf.String() != body {
			t.Errorf("body after tee-read = %q, want %q", buf.String(), body)
		}
	})

	t.Run("binary body not sampled", func(t *testing.T) {
		body := []byte{0x89, 0x50, 0x4e, 0x47} // PNG header
		req, _ := http.NewRequest("POST", "http://example.com", bytes.NewReader(body))
		req.Header.Set("Content-Type", "image/png")
		sample, hash, size := readRequestBody(req)
		if sample != "" {
			t.Errorf("binary body should not be sampled, got %q", sample)
		}
		if hash == "" {
			t.Error("hash should still be computed for binary")
		}
		if size != int64(len(body)) {
			t.Errorf("size = %d, want %d", size, len(body))
		}
	})
}

func TestRedactHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret")
	h.Set("Cookie", "session=abc")
	h.Set("X-Api-Key", "key123")
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "test/1.0")

	redacted := redactHeaders(h)

	if redacted["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization not redacted: %q", redacted["Authorization"])
	}
	if redacted["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie not redacted: %q", redacted["Cookie"])
	}
	if redacted["X-Api-Key"] != "[REDACTED]" {
		t.Errorf("X-Api-Key not redacted: %q", redacted["X-Api-Key"])
	}
	if redacted["Content-Type"] != "application/json" {
		t.Errorf("Content-Type should not be redacted: %q", redacted["Content-Type"])
	}
}

func TestColorDecision(t *testing.T) {
	// Just verify it doesn't panic
	_ = colorDecision(types.DecisionAllow)
	_ = colorDecision(types.DecisionBlock)
	_ = colorDecision(types.DecisionFlag)
}
