package types

import "testing"

func TestDecisionString(t *testing.T) {
	tests := []struct {
		d    Decision
		want string
	}{
		{DecisionAllow, "allow"},
		{DecisionBlock, "block"},
		{DecisionFlag, "flag"},
		{Decision(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("Decision(%d).String() = %q, want %q", tt.d, got, tt.want)
		}
	}
}
