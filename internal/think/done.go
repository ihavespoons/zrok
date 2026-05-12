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

// DoneOptions configures the completion check.
type DoneOptions struct {
	// Agent is the agent name to evaluate.
	Agent string
}

// DoneReport scores how complete an agent's work is.
type DoneReport struct {
	Agent            string             `json:"agent"`
	OwnedCWEs        []string           `json:"owned_cwes"`
	CWECoverage      []CWECoverage      `json:"cwe_coverage"`
	RequiredMemories []string           `json:"required_memories"`
	MissingMemories  []string           `json:"missing_memories,omitempty"`
	OpenFindings     int                `json:"open_findings"`
	ConfirmedFindings int               `json:"confirmed_findings"`
	FalsePositives   int                `json:"false_positives"`
	CompletenessPct  int                `json:"completeness_pct"`
	Recommendation   string             `json:"recommendation"`
	Notes            []string           `json:"notes,omitempty"`
}

// CWECoverage indicates whether the agent produced any findings (or an
// explicit no-findings memory) for one CWE.
type CWECoverage struct {
	CWE             string `json:"cwe"`
	FindingCount    int    `json:"finding_count"`
	HasNullResult   bool   `json:"has_null_result"`
}

// AnalyzeDone scores an agent's completeness on its declared CWEs.
func AnalyzeDone(p *project.Project, opts DoneOptions) (*DoneReport, error) {
	if opts.Agent == "" {
		return nil, fmt.Errorf("--agent is required")
	}

	ag := agent.GetBuiltinAgent(opts.Agent)
	if ag == nil {
		return nil, fmt.Errorf("agent %q not found", opts.Agent)
	}

	r := &DoneReport{Agent: opts.Agent}
	for _, c := range ag.CWEChecklist {
		r.OwnedCWEs = append(r.OwnedCWEs, c.ID)
	}
	sort.Strings(r.OwnedCWEs)
	r.RequiredMemories = append(r.RequiredMemories, ag.ContextMemories...)
	sort.Strings(r.RequiredMemories)

	// Findings by this agent.
	store := finding.NewStore(p)
	list, err := store.List(nil)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	byCWE := map[string]int{}
	for _, f := range list.Findings {
		if f.CreatedBy != opts.Agent {
			continue
		}
		byCWE[strings.ToUpper(f.CWE)]++
		switch f.Status {
		case finding.StatusOpen:
			r.OpenFindings++
		case finding.StatusConfirmed:
			r.ConfirmedFindings++
		case finding.StatusFalsePositive:
			r.FalsePositives++
		}
	}

	// Memories present.
	memStore := memory.NewStore(p)
	defer func() { _ = memStore.Close() }()
	memList, err := memStore.List("")
	if err != nil {
		return nil, fmt.Errorf("list memories: %w", err)
	}
	memPresent := map[string]string{}
	for _, m := range memList.Memories {
		memPresent[m.Name] = m.Content
	}

	// Missing memories.
	for _, name := range r.RequiredMemories {
		if _, ok := memPresent[name]; !ok {
			r.MissingMemories = append(r.MissingMemories, name)
		}
	}

	// CWE coverage: a CWE is "covered" if any finding exists, OR
	// a memory body explicitly says "no findings for CWE-XXX".
	for _, c := range ag.CWEChecklist {
		cov := CWECoverage{CWE: c.ID, FindingCount: byCWE[strings.ToUpper(c.ID)]}
		if cov.FindingCount == 0 {
			for _, body := range memPresent {
				if strings.Contains(body, "no findings for "+c.ID) ||
					strings.Contains(body, "no "+c.ID+" findings") ||
					strings.Contains(body, "No "+c.ID) {
					cov.HasNullResult = true
					break
				}
			}
		}
		r.CWECoverage = append(r.CWECoverage, cov)
	}

	// Score completeness:
	//   60% weighted: fraction of required memories present
	//   40% weighted: fraction of CWEs with findings OR an explicit null result
	memScore := 1.0
	if len(r.RequiredMemories) > 0 {
		memScore = float64(len(r.RequiredMemories)-len(r.MissingMemories)) / float64(len(r.RequiredMemories))
	}
	cweScore := 1.0
	if len(r.CWECoverage) > 0 {
		covered := 0
		for _, c := range r.CWECoverage {
			if c.FindingCount > 0 || c.HasNullResult {
				covered++
			}
		}
		cweScore = float64(covered) / float64(len(r.CWECoverage))
	}
	r.CompletenessPct = int((memScore*0.6 + cweScore*0.4) * 100)

	switch {
	case r.CompletenessPct >= 90:
		r.Recommendation = "proceed_to_report"
	case r.CompletenessPct >= 60:
		r.Recommendation = "address_gaps"
	default:
		r.Recommendation = "continue_analysis"
	}

	return r, nil
}

// RenderDoneText renders a text view.
func RenderDoneText(r *DoneReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Completion Assessment: %s\n\n", r.Agent)
	fmt.Fprintf(&b, "Completeness:       %d%%\n", r.CompletenessPct)
	fmt.Fprintf(&b, "Recommendation:     %s\n\n", r.Recommendation)
	fmt.Fprintf(&b, "Owned CWEs:         %s\n", strings.Join(r.OwnedCWEs, ", "))
	fmt.Fprintf(&b, "Required memories:  %s\n", strings.Join(r.RequiredMemories, ", "))
	if len(r.MissingMemories) > 0 {
		fmt.Fprintf(&b, "Missing memories:   %s\n", strings.Join(r.MissingMemories, ", "))
	}
	fmt.Fprintf(&b, "\nFindings: %d open / %d confirmed / %d false-positive\n\n", r.OpenFindings, r.ConfirmedFindings, r.FalsePositives)

	fmt.Fprintf(&b, "### CWE Coverage\n")
	for _, c := range r.CWECoverage {
		state := "MISSING"
		switch {
		case c.FindingCount > 0:
			state = fmt.Sprintf("findings=%d", c.FindingCount)
		case c.HasNullResult:
			state = "explicit no-findings"
		}
		fmt.Fprintf(&b, "  - %s: %s\n", c.CWE, state)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}
