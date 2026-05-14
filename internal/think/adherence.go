package think

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ihavespoons/quokka/internal/agent"
	"github.com/ihavespoons/quokka/internal/finding"
	"github.com/ihavespoons/quokka/internal/project"
)

// AdherenceOptions configures the adherence check.
type AdherenceOptions struct {
	// Agent is the agent name to check (required for the typical use).
	// If empty, every agent that has produced findings is evaluated.
	Agent string
	// Task is an optional free-form task description, kept for backward
	// compatibility with the old prompt verb.
	Task string
}

// AdherenceReport reports which findings/memories are out of an agent's scope.
type AdherenceReport struct {
	Agent          string             `json:"agent,omitempty"`
	Task           string             `json:"task,omitempty"`
	OwnedCWEs      []string           `json:"owned_cwes,omitempty"`
	InScope        []FindingRef       `json:"in_scope,omitempty"`
	OutOfScope     []FindingRef       `json:"out_of_scope,omitempty"`
	UnknownAgents  []string           `json:"unknown_agents,omitempty"`
	Notes          []string           `json:"notes,omitempty"`
}

// FindingRef is a compact reference to a finding for adherence/done reports.
type FindingRef struct {
	ID      string `json:"id"`
	CWE     string `json:"cwe"`
	Title   string `json:"title"`
	Created string `json:"created_by"`
}

// AnalyzeAdherence checks whether findings created by an agent fall inside
// that agent's declared CWE scope.
func AnalyzeAdherence(p *project.Project, opts AdherenceOptions) (*AdherenceReport, error) {
	r := &AdherenceReport{
		Agent: opts.Agent,
		Task:  opts.Task,
	}

	if opts.Agent == "" {
		r.Notes = append(r.Notes, "no --agent provided; reporting only known agents from findings")
	}

	// Load builtin agents.
	agents := agent.GetBuiltinAgents()
	agentByName := map[string]*agent.AgentConfig{}
	for i := range agents {
		agentByName[agents[i].Name] = &agents[i]
	}

	// Resolve the target agent's owned CWEs.
	var ownedCWEs map[string]bool
	if opts.Agent != "" {
		ag, ok := agentByName[opts.Agent]
		if !ok {
			return nil, fmt.Errorf("agent %q not found", opts.Agent)
		}
		ownedCWEs = map[string]bool{}
		for _, c := range ag.CWEChecklist {
			ownedCWEs[strings.ToUpper(c.ID)] = true
			r.OwnedCWEs = append(r.OwnedCWEs, c.ID)
		}
		sort.Strings(r.OwnedCWEs)
	}

	// List findings.
	store := finding.NewStore(p)
	list, err := store.List(nil)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}

	unknownSeen := map[string]bool{}
	for _, f := range list.Findings {
		if opts.Agent != "" && f.CreatedBy != opts.Agent {
			continue
		}

		ref := FindingRef{ID: f.ID, CWE: f.CWE, Title: f.Title, Created: f.CreatedBy}

		// If we don't know what the agent owns, just record.
		if ownedCWEs == nil {
			if f.CreatedBy != "" {
				if _, known := agentByName[f.CreatedBy]; !known {
					if !unknownSeen[f.CreatedBy] {
						unknownSeen[f.CreatedBy] = true
						r.UnknownAgents = append(r.UnknownAgents, f.CreatedBy)
					}
				}
			}
			continue
		}

		if f.CWE == "" {
			// Treat empty CWE as out-of-scope unless agent owns no CWEs.
			if len(ownedCWEs) > 0 {
				r.OutOfScope = append(r.OutOfScope, ref)
			} else {
				r.InScope = append(r.InScope, ref)
			}
			continue
		}

		if ownedCWEs[strings.ToUpper(f.CWE)] {
			r.InScope = append(r.InScope, ref)
		} else {
			r.OutOfScope = append(r.OutOfScope, ref)
		}
	}

	sort.Strings(r.UnknownAgents)
	sortRefs(r.InScope)
	sortRefs(r.OutOfScope)

	return r, nil
}

func sortRefs(refs []FindingRef) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
}

// RenderAdherenceText renders a text view.
func RenderAdherenceText(r *AdherenceReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Adherence Check\n\n")
	if r.Agent != "" {
		fmt.Fprintf(&b, "Agent:       %s\n", r.Agent)
		fmt.Fprintf(&b, "Owned CWEs:  %s\n\n", strings.Join(r.OwnedCWEs, ", "))
	}
	if r.Task != "" {
		fmt.Fprintf(&b, "Task:        %s\n\n", r.Task)
	}

	fmt.Fprintf(&b, "In scope:     %d\n", len(r.InScope))
	fmt.Fprintf(&b, "Out of scope: %d\n", len(r.OutOfScope))

	if len(r.OutOfScope) > 0 {
		fmt.Fprintf(&b, "\n### Out-of-scope findings:\n")
		for _, f := range r.OutOfScope {
			fmt.Fprintf(&b, "  - %s [%s] %s  (by %s)\n", f.ID, f.CWE, f.Title, f.Created)
		}
	}

	if len(r.UnknownAgents) > 0 {
		fmt.Fprintf(&b, "\nUnknown agents seen in findings: %s\n", strings.Join(r.UnknownAgents, ", "))
	}

	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}
