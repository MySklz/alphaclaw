// Package notify sends webhook notifications on block/flag/ban events.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kumo-ai/kumo/pkg/types"
)

// WebhookNotifier sends events to a configured webhook URL.
type WebhookNotifier struct {
	url    string
	on     map[string]bool
	client *http.Client
}

// NewWebhookNotifier creates a notifier. If url is empty, notifications are disabled.
func NewWebhookNotifier(url string, eventTypes []string) *WebhookNotifier {
	on := make(map[string]bool)
	for _, t := range eventTypes {
		on[t] = true
	}

	return &WebhookNotifier{
		url: url,
		on:  on,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Notify sends an event to the webhook URL. Fire-and-forget: errors are logged
// but never block the proxy or affect the request decision.
func (n *WebhookNotifier) Notify(ctx context.Context, event types.NotifyEvent) error {
	if n.url == "" {
		return nil
	}

	if !n.on[event.Type] {
		return nil
	}

	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("WARNING: webhook marshal error: %v", err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.url, bytes.NewReader(body))
	if err != nil {
		log.Printf("WARNING: webhook request error: %v", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kumo-webhook/1.0")

	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("WARNING: webhook delivery failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("WARNING: webhook returned %d", resp.StatusCode)
	}

	return nil
}
