package policy

import (
	"testing"
	"time"
)

func TestBanManager(t *testing.T) {
	bm := NewBanManager(BanConfig{
		MaxViolations: 3,
		BanDuration:   "1h",
		Message:       "Banned!",
	})

	// Initially not banned
	if bm.IsBanned("tok_jim") {
		t.Error("should not be banned initially")
	}

	// First violation
	count, banned := bm.RecordViolation("tok_jim", "rule1")
	if count != 1 || banned {
		t.Errorf("first violation: count=%d banned=%v", count, banned)
	}

	// Second violation (same rule)
	count, banned = bm.RecordViolation("tok_jim", "rule1")
	if count != 2 || banned {
		t.Errorf("second violation: count=%d banned=%v", count, banned)
	}

	// Third violation triggers ban
	count, banned = bm.RecordViolation("tok_jim", "rule1")
	if count != 3 || !banned {
		t.Errorf("third violation: count=%d banned=%v", count, banned)
	}

	// Now banned
	if !bm.IsBanned("tok_jim") {
		t.Error("should be banned after 3 violations")
	}
}

func TestBanManagerDifferentRules(t *testing.T) {
	bm := NewBanManager(BanConfig{
		MaxViolations: 3,
		BanDuration:   "1h",
	})

	// Violate 3 different rules once each
	bm.RecordViolation("tok_jim", "rule1")
	bm.RecordViolation("tok_jim", "rule2")
	bm.RecordViolation("tok_jim", "rule3")

	// Should NOT be banned (different rules)
	if bm.IsBanned("tok_jim") {
		t.Error("should not be banned for different rules")
	}
}

func TestBanManagerDifferentAgents(t *testing.T) {
	bm := NewBanManager(BanConfig{
		MaxViolations: 2,
		BanDuration:   "1h",
	})

	// Agent A violates rule1 twice → banned
	bm.RecordViolation("tok_a", "rule1")
	bm.RecordViolation("tok_a", "rule1")

	if !bm.IsBanned("tok_a") {
		t.Error("agent A should be banned")
	}

	// Agent B is not affected
	if bm.IsBanned("tok_b") {
		t.Error("agent B should not be banned")
	}
}

func TestBanManagerExpiry(t *testing.T) {
	bm := NewBanManager(BanConfig{
		MaxViolations: 1,
		BanDuration:   "1ms", // very short for testing
	})

	bm.RecordViolation("tok_jim", "rule1")
	if !bm.IsBanned("tok_jim") {
		t.Error("should be banned immediately")
	}

	time.Sleep(10 * time.Millisecond)

	if bm.IsBanned("tok_jim") {
		t.Error("ban should have expired")
	}
}
