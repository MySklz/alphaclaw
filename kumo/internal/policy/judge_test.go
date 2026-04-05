package policy

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRingBuffer(t *testing.T) {
	rb := NewRingBuffer(3)

	rb.Add(LookbackEntry{Method: "GET", Path: "/a"})
	rb.Add(LookbackEntry{Method: "GET", Path: "/b"})

	got := rb.Last(5) // request more than available
	if len(got) != 2 {
		t.Errorf("Last(5) = %d entries, want 2", len(got))
	}

	rb.Add(LookbackEntry{Method: "GET", Path: "/c"})
	rb.Add(LookbackEntry{Method: "GET", Path: "/d"}) // evicts /a

	got = rb.Last(3)
	if len(got) != 3 {
		t.Fatalf("Last(3) = %d entries, want 3", len(got))
	}
	if got[0].Path != "/b" {
		t.Errorf("oldest entry = %q, want /b", got[0].Path)
	}
	if got[2].Path != "/d" {
		t.Errorf("newest entry = %q, want /d", got[2].Path)
	}
}

func TestRingBuffer_Concurrent(t *testing.T) {
	rb := NewRingBuffer(100)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				rb.Add(LookbackEntry{Method: "GET", Path: "/test"})
				rb.Last(10)
			}
		}(i)
	}
	wg.Wait()

	got := rb.Last(100)
	if len(got) != 100 {
		t.Errorf("after concurrent access: %d entries, want 100", len(got))
	}
}

func TestLookbackManager(t *testing.T) {
	lm := NewLookbackManager(50)

	lm.Record("tok_a", LookbackEntry{Method: "GET", Path: "/a1", Timestamp: time.Now()})
	lm.Record("tok_a", LookbackEntry{Method: "POST", Path: "/a2", Timestamp: time.Now()})
	lm.Record("tok_b", LookbackEntry{Method: "GET", Path: "/b1", Timestamp: time.Now()})

	a := lm.GetLookback("tok_a", 10)
	if len(a) != 2 {
		t.Errorf("tok_a lookback = %d, want 2", len(a))
	}

	b := lm.GetLookback("tok_b", 10)
	if len(b) != 1 {
		t.Errorf("tok_b lookback = %d, want 1", len(b))
	}

	c := lm.GetLookback("tok_unknown", 10)
	if c != nil {
		t.Errorf("unknown token should return nil, got %v", c)
	}
}

func TestStubJudgeClient(t *testing.T) {
	client := &StubJudgeClient{}
	result, err := client.Judge(context.Background(), JudgeRequest{
		Method: "GET",
		Path:   "/test",
	})
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if result.Decision != "flag" {
		t.Errorf("decision = %q, want 'flag'", result.Decision)
	}
}

func TestFormatLookback(t *testing.T) {
	entries := []LookbackEntry{
		{Timestamp: time.Now(), Method: "GET", Host: "api.example.com", Path: "/test", Status: 200, Decision: "allow"},
	}
	formatted := FormatLookback(entries)
	if formatted == "" {
		t.Error("formatted lookback should not be empty")
	}

	empty := FormatLookback(nil)
	if empty != "No recent traffic history." {
		t.Errorf("empty lookback = %q", empty)
	}
}
