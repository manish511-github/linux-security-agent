package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type Action string

const (
	Allow Action = "allow"
	Block Action = "block"
)

type Rule struct {
	Domain string `json:"domain"`
	Action Action `json:"action"`
	Reason string `json:"reason,omitempty"`
}

type Engine struct {
	Version       int    `json:"version"`
	DefaultAction Action `json:"default_action"`
	Rules         []Rule `json:"rules"`
}

type Decision struct {
	Action Action
	Reason string
}

func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var engine Engine
	if err := json.Unmarshal(data, &engine); err != nil {
		return nil, err
	}
	if err := engine.validate(); err != nil {
		return nil, err
	}
	return &engine, nil
}

func (e Engine) Evaluate(domain string) Decision {
	domain = normalizeDomain(domain)
	for _, rule := range e.Rules {
		if matchesDomain(domain, normalizeDomain(rule.Domain)) {
			return Decision{Action: rule.Action, Reason: rule.Reason}
		}
	}
	return Decision{Action: e.DefaultAction}
}

func (e Engine) validate() error {
	if e.Version < 1 {
		return fmt.Errorf("version must be at least 1")
	}
	if !validAction(e.DefaultAction) {
		return fmt.Errorf("invalid default action %q", e.DefaultAction)
	}
	for index, rule := range e.Rules {
		if normalizeDomain(rule.Domain) == "" {
			return fmt.Errorf("rule %d has an empty domain", index)
		}
		if !validAction(rule.Action) {
			return fmt.Errorf("rule %d has invalid action %q", index, rule.Action)
		}
	}
	return nil
}

func validAction(action Action) bool {
	return action == Allow || action == Block
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func matchesDomain(domain, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(domain, suffix) && domain != strings.TrimPrefix(suffix, ".")
	}
	return domain == pattern
}
