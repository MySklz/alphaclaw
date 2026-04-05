package policy

import (
	"sync"
	"time"
)

// BanManager tracks per-agent per-rule violations and enforces bans.
//
// Violation counting:
//   agent_token + rule_name → violation count
//   Ban triggers at max_violations for the SAME rule.
//   Different rules violated once each do NOT trigger a ban.
type BanManager struct {
	mu          sync.RWMutex
	violations  map[banKey]int
	bans        map[string]time.Time // token → ban expiry
	maxViolate  int
	banDuration time.Duration
	banMessage  string
}

type banKey struct {
	token string
	rule  string
}

// NewBanManager creates a new ban manager from config.
func NewBanManager(cfg BanConfig) *BanManager {
	dur, _ := time.ParseDuration(cfg.BanDuration)
	if dur == 0 {
		dur = 1 * time.Hour
	}

	maxV := cfg.MaxViolations
	if maxV == 0 {
		maxV = 3
	}

	return &BanManager{
		violations:  make(map[banKey]int),
		bans:        make(map[string]time.Time),
		maxViolate:  maxV,
		banDuration: dur,
		banMessage:  cfg.Message,
	}
}

// IsBanned checks if an agent token is currently banned.
func (bm *BanManager) IsBanned(token string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	expiry, ok := bm.bans[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		// Ban expired, will be cleaned up on next violation
		return false
	}
	return true
}

// RecordViolation records a policy violation and returns the current count
// and whether the agent is now banned.
func (bm *BanManager) RecordViolation(token, rule string) (violations int, banned bool) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Clean expired ban if any
	if expiry, ok := bm.bans[token]; ok && time.Now().After(expiry) {
		delete(bm.bans, token)
		// Reset violation count for this rule after ban expires
		delete(bm.violations, banKey{token, rule})
	}

	key := banKey{token, rule}
	bm.violations[key]++
	count := bm.violations[key]

	if count >= bm.maxViolate {
		bm.bans[token] = time.Now().Add(bm.banDuration)
		return count, true
	}

	return count, false
}

// BanMessage returns the configured ban message.
func (bm *BanManager) BanMessage() string {
	if bm.banMessage != "" {
		return bm.banMessage
	}
	return "You have been temporarily suspended for attempting to circumvent security restrictions."
}

// MaxViolations returns the configured max violations before ban.
func (bm *BanManager) MaxViolations() int {
	return bm.maxViolate
}

// ViolationCount returns the current violation count for a token+rule pair.
func (bm *BanManager) ViolationCount(token, rule string) int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.violations[banKey{token, rule}]
}
