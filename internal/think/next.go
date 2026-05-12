package think

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ihavespoons/zrok/internal/agent"
	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/memory"
	"github.com/ihavespoons/zrok/internal/project"
)

// NextOptions configures the next-step recommender.
type NextOptions struct {
	// MaxSteps caps how many ranked steps to return (default 10).
	MaxSteps int
}

// NextStep is one ranked next action.
type NextStep struct {
	Rank     int    `json:"rank"`
	Priority string `json:"priority"` // high | medium | low
	Action   string `json:"action"`
	Reason   string `json:"reason"`
	Command  string `json:"command,omitempty"`
}

// NextReport is a ranked checklist of recommended actions.
type NextReport struct {
	OpenHighSev      int        `json:"open_high_severity"`
	MissingMemories  []string   `json:"missing_memories,omitempty"`
	UncoveredCWEs    []string   `json:"uncovered_cwes,omitempty"`
	OpenWithoutCWE   []string   `json:"open_findings_without_cwe,omitempty"`
	Steps            []NextStep `json:"steps"`
	Notes            []string   `json:"notes,omitempty"`
}

// AnalyzeNext computes prioritized next steps based on current findings,
// memories, and agent coverage.
func AnalyzeNext(p *project.Project, opts NextOptions) (*NextReport, error) {
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = 10
	}

	r := &NextReport{}

	// Load findings.
	fStore := finding.NewStore(p)
	fList, err := fStore.List(nil)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}

	// Load memories.
	mStore := memory.NewStore(p)
	defer func() { _ = mStore.Close() }()
	mList, err := mStore.List("")
	if err != nil {
		return nil, fmt.Errorf("list memories: %w", err)
	}
	memPresent := map[string]bool{}
	for _, m := range mList.Memories {
		memPresent[m.Name] = true
	}

	// Count open findings + open severity buckets, and detect issues.
	cweSeen := map[string]bool{}
	for _, f := range fList.Findings {
		if f.CWE != "" {
			cweSeen[strings.ToUpper(f.CWE)] = true
		}
		if f.Status == finding.StatusOpen {
			if f.Severity == finding.SeverityHigh || f.Severity == finding.SeverityCritical {
				r.OpenHighSev++
			}
			if f.CWE == "" {
				r.OpenWithoutCWE = append(r.OpenWithoutCWE, f.ID)
			}
		}
	}
	sort.Strings(r.OpenWithoutCWE)

	// Applicable agents (by project classification).
	var applicable []agent.AgentConfig
	if p != nil && p.Config != nil {
		for _, ag := range agent.GetBuiltinAgents() {
			if project.ApplicabilityMatches(ag.Applicability, p.Config.Classification) {
				applicable = append(applicable, ag)
			}
		}
	}

	// Missing memories.
	expectedMems := map[string]bool{}
	for _, ag := range applicable {
		for _, m := range ag.ContextMemories {
			expectedMems[m] = true
		}
	}
	for m := range expectedMems {
		if !memPresent[m] {
			r.MissingMemories = append(r.MissingMemories, m)
		}
	}
	sort.Strings(r.MissingMemories)

	// Uncovered CWEs (declared by applicable agents but not seen in any finding).
	declaredCWEs := map[string]bool{}
	for _, ag := range applicable {
		for _, c := range ag.CWEChecklist {
			declaredCWEs[strings.ToUpper(c.ID)] = true
		}
	}
	for cwe := range declaredCWEs {
		if !cweSeen[cwe] {
			r.UncoveredCWEs = append(r.UncoveredCWEs, cwe)
		}
	}
	sort.Strings(r.UncoveredCWEs)

	// Now rank steps by impact.
	if r.OpenHighSev > 0 {
		r.Steps = append(r.Steps, NextStep{
			Priority: "high",
			Action:   fmt.Sprintf("Validate %d open high/critical findings", r.OpenHighSev),
			Reason:   "high-severity findings still in open state",
			Command:  `zrok finding list --severity high --status open`,
		})
	}
	if len(r.MissingMemories) > 0 {
		r.Steps = append(r.Steps, NextStep{
			Priority: "high",
			Action:   fmt.Sprintf("Create %d missing context memories", len(r.MissingMemories)),
			Reason:   "agents declare these as required context: " + strings.Join(r.MissingMemories, ", "),
			Command:  `zrok memory write <name> --type context --content "..."`,
		})
	}
	if len(r.UncoveredCWEs) > 0 {
		r.Steps = append(r.Steps, NextStep{
			Priority: "medium",
			Action:   fmt.Sprintf("Investigate %d uncovered CWEs", len(r.UncoveredCWEs)),
			Reason:   "applicable agents own these but no findings exist yet: " + strings.Join(r.UncoveredCWEs, ", "),
			Command:  `zrok think hypothesis`,
		})
	}
	if len(r.OpenWithoutCWE) > 0 {
		r.Steps = append(r.Steps, NextStep{
			Priority: "medium",
			Action:   "Triage open findings missing CWE tags",
			Reason:   "without CWE these can't be evaluated for adherence/coverage: " + strings.Join(r.OpenWithoutCWE, ", "),
			Command:  `zrok finding update <id> --cwe CWE-XXX`,
		})
	}
	if fList.Total == 0 {
		r.Steps = append(r.Steps, NextStep{
			Priority: "high",
			Action:   "Run recon then primary analysis agents",
			Reason:   "no findings recorded yet",
			Command:  `zrok agent list`,
		})
	}
	if len(r.Steps) == 0 {
		r.Steps = append(r.Steps, NextStep{
			Priority: "low",
			Action:   "Export findings and finalize report",
			Reason:   "no outstanding gaps detected",
			Command:  `zrok finding export --format markdown`,
		})
	}

	for i := range r.Steps {
		r.Steps[i].Rank = i + 1
	}
	if len(r.Steps) > opts.MaxSteps {
		r.Steps = r.Steps[:opts.MaxSteps]
	}

	return r, nil
}

// RenderNextText renders a text view.
func RenderNextText(r *NextReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Next-Step Plan\n\n")
	fmt.Fprintf(&b, "Open high/critical findings: %d\n", r.OpenHighSev)
	if len(r.MissingMemories) > 0 {
		fmt.Fprintf(&b, "Missing memories:            %s\n", strings.Join(r.MissingMemories, ", "))
	}
	if len(r.UncoveredCWEs) > 0 {
		fmt.Fprintf(&b, "Uncovered CWEs:              %s\n", strings.Join(r.UncoveredCWEs, ", "))
	}
	fmt.Fprintf(&b, "\n### Ranked Steps\n")
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "%d. [%s] %s\n", s.Rank, s.Priority, s.Action)
		fmt.Fprintf(&b, "   reason:  %s\n", s.Reason)
		if s.Command != "" {
			fmt.Fprintf(&b, "   command: %s\n", s.Command)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}
