// Package rule manages project-local opengrep rules and their provenance.
//
// Rules live as opengrep-compatible YAML files in .zrok/rules/<slug>.yaml.
// Each rule has a sidecar metadata file <slug>.zmeta.yaml that records who
// authored it, why, and any verdict from the rule-judge-agent. Splitting
// metadata into a sidecar keeps the rule file pure opengrep syntax — the
// SAST runner can scan the directory without seeing zrok-internal fields.
package rule

import (
	"fmt"
	"strings"
	"time"
)

// Verdict is the rule-judge-agent's assessment of an accumulated rule.
type Verdict string

const (
	// VerdictUnknown is the initial state — judge hasn't evaluated yet.
	VerdictUnknown Verdict = ""

	// VerdictKeep — rule fires periodically with low FP ratio. No action.
	VerdictKeep Verdict = "keep"

	// VerdictRefine — high FP ratio (>50%). Judge proposes a tighter pattern;
	// human or downstream agent should review the suggestion.
	VerdictRefine Verdict = "refine"

	// VerdictRetire — no fires in N days, FP ratio >80%, or subsumed by
	// another rule. Stored as disabled: true on the rule itself; the file
	// stays for archaeology.
	VerdictRetire Verdict = "retire"

	// VerdictEscalate — judge cannot decide; needs a human reviewer.
	VerdictEscalate Verdict = "escalate"
)

// ValidVerdicts contains every Verdict accepted by Annotate.
var ValidVerdicts = []Verdict{
	VerdictKeep, VerdictRefine, VerdictRetire, VerdictEscalate,
}

// IsValidVerdict reports whether v is a recognized verdict.
func IsValidVerdict(v Verdict) bool {
	for _, valid := range ValidVerdicts {
		if v == valid {
			return true
		}
	}
	return false
}

// Meta is the sidecar provenance and judge state for a rule. Stored in
// .zrok/rules/<slug>.zmeta.yaml — opengrep ignores it (different extension)
// while zrok uses it to track origin, trigger counts, and verdicts over time.
type Meta struct {
	Slug         string    `yaml:"slug" json:"slug"`
	CreatedBy    string    `yaml:"created_by" json:"created_by"`         // e.g. "agent:injection-agent" or "human:alice"
	CreatedAt    time.Time `yaml:"created_at" json:"created_at"`
	CreatedFor   string    `yaml:"created_for,omitempty" json:"created_for,omitempty"` // e.g. "PR #482"
	Reasoning    string    `yaml:"reasoning,omitempty" json:"reasoning,omitempty"`
	Verdict      Verdict   `yaml:"verdict,omitempty" json:"verdict,omitempty"`
	VerdictNote  string    `yaml:"verdict_note,omitempty" json:"verdict_note,omitempty"`
	LastAuditAt  time.Time `yaml:"last_audit_at,omitempty" json:"last_audit_at,omitempty"`
	TriggerCount int       `yaml:"trigger_count,omitempty" json:"trigger_count,omitempty"`
	FPCount      int       `yaml:"fp_count,omitempty" json:"fp_count,omitempty"`
	Disabled     bool      `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

// Validate checks required fields on the metadata. Reasoning is encouraged
// but not enforced — humans authoring rules manually may not write a
// paragraph, and the field's main value is for agent-authored rules.
func (m Meta) Validate() error {
	if strings.TrimSpace(m.Slug) == "" {
		return fmt.Errorf("slug is required")
	}
	if strings.TrimSpace(m.CreatedBy) == "" {
		return fmt.Errorf("created_by is required (e.g. \"agent:injection-agent\" or \"human:alice\")")
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("created_at is required")
	}
	return nil
}

// RuleFile is the parsed shape of the opengrep YAML at .zrok/rules/<slug>.yaml.
// We only validate enough structure to fail-fast on syntactic mistakes;
// opengrep does real semantic validation when scanning.
type RuleFile struct {
	Rules []RuleEntry `yaml:"rules" json:"rules"`
}

// RuleEntry is one rule definition inside a RuleFile. The full opengrep rule
// schema is large; we only model the fields zrok cares about for validation
// and listing. Unknown fields are preserved on disk as raw YAML.
type RuleEntry struct {
	ID        string   `yaml:"id" json:"id"`
	Message   string   `yaml:"message,omitempty" json:"message,omitempty"`
	Severity  string   `yaml:"severity,omitempty" json:"severity,omitempty"`
	Languages []string `yaml:"languages,omitempty" json:"languages,omitempty"`
	Pattern   string   `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	// Patterns is intentionally interface — opengrep allows nested
	// pattern-either/pattern-not/etc structures we don't fully model.
	Patterns interface{} `yaml:"patterns,omitempty" json:"patterns,omitempty"`
}

// ValidateStructure checks that the file has the required opengrep shape.
// Fails fast on malformed input so zrok rule add rejects bad rules at
// authoring time instead of leaving the user to discover the failure on
// the next zrok sast run.
func (rf RuleFile) ValidateStructure() error {
	if len(rf.Rules) == 0 {
		return fmt.Errorf("rule file must define at least one rule under \"rules:\"")
	}
	seen := map[string]bool{}
	for i, r := range rf.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("rule[%d]: id is required", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule[%d]: duplicate id %q within this file", i, r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Message) == "" {
			return fmt.Errorf("rule %q: message is required (opengrep displays this when the rule fires)", r.ID)
		}
		if r.Pattern == "" && r.Patterns == nil {
			return fmt.Errorf("rule %q: must define pattern or patterns", r.ID)
		}
	}
	return nil
}
