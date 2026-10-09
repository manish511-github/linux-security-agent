package policy

import "testing"

func TestEvaluate(t *testing.T) {
	engine := Engine{
		Version:       1,
		DefaultAction: Allow,
		Rules: []Rule{
			{Domain: "blocked.example", Action: Block, Reason: "company policy"},
			{Domain: "*.social.example", Action: Block},
		},
	}

	tests := []struct {
		domain string
		want   Action
	}{
		{"blocked.example", Block},
		{"BLOCKED.EXAMPLE.", Block},
		{"chat.social.example", Block},
		{"social.example", Allow},
		{"allowed.example", Allow},
	}

	for _, test := range tests {
		t.Run(test.domain, func(t *testing.T) {
			if got := engine.Evaluate(test.domain).Action; got != test.want {
				t.Fatalf("Evaluate(%q) = %q, want %q", test.domain, got, test.want)
			}
		})
	}
}

func TestValidateRejectsUnknownAction(t *testing.T) {
	engine := Engine{Version: 1, DefaultAction: "sometimes"}
	if err := engine.validate(); err == nil {
		t.Fatal("validate() accepted an unknown action")
	}
}
