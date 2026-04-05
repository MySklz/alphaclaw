package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kumo-ai/kumo/pkg/types"
)

func TestWebhookNotifier_Send(t *testing.T) {
	received := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(200)
		received <- true
	}))
	defer server.Close()

	n := NewWebhookNotifier(server.URL, []string{"block", "flag"})
	err := n.Notify(context.Background(), types.NotifyEvent{
		Type:      "block",
		AgentName: "jim",
		Rule:      "block_feedback",
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Errorf("Notify: %v", err)
	}

	select {
	case <-received:
		// ok
	case <-time.After(2 * time.Second):
		t.Error("webhook not received")
	}
}

func TestWebhookNotifier_FilteredOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not have been called")
	}))
	defer server.Close()

	n := NewWebhookNotifier(server.URL, []string{"block"}) // only block events
	n.Notify(context.Background(), types.NotifyEvent{
		Type: "flag", // not in the "on" list
	})
}

func TestWebhookNotifier_EmptyURL(t *testing.T) {
	n := NewWebhookNotifier("", []string{"block"})
	err := n.Notify(context.Background(), types.NotifyEvent{Type: "block"})
	if err != nil {
		t.Errorf("empty URL should be no-op, got: %v", err)
	}
}

func TestWebhookNotifier_Unreachable(t *testing.T) {
	n := NewWebhookNotifier("http://localhost:1", []string{"block"})
	err := n.Notify(context.Background(), types.NotifyEvent{Type: "block"})
	// Should not return error (fire-and-forget)
	if err != nil {
		t.Errorf("unreachable should not error: %v", err)
	}
}
