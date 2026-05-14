package think

import (
	"fmt"
	"sort"
	"strings"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/memory"
	"github.com/diffsec/quokka/internal/project"
)

// CollectedOptions configures the collected-context audit.
type CollectedOptions struct {
	// Memories optionally restricts the audit to a subset of memory names.
	Memories []string
}

// CollectedReport audits whether the memory context is coherent.
type CollectedReport struct {
	PresentMemories []string          `json:"present_memories"`
	MissingExpected []MissingMemory   `json:"missing_expected,omitempty"`
	CrossReferences []CrossReference  `json:"cross_references,omitempty"`
	OrphanMemories  []string          `json:"orphan_memories,omitempty"`
	Notes           []string          `json:"notes,omitempty"`
}

// MissingMemory is a memory expected by some agent but not present.
type MissingMemory struct {
	Name           string   `json:"name"`
	ExpectedByAgents []string `json:"expected_by_agents"`
}

// CrossReference records that memory A's content mentions memory B.
type CrossReference struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// AnalyzeCollected audits the memory store against the agents' declared
// context_memories and looks for cross-references between memory bodies.
func AnalyzeCollected(p *project.Project, opts CollectedOptions) (*CollectedReport, error) {
	store := memory.NewStore(p)
	defer func() { _ = store.Close() }()

	list, err := store.List("")
	if err != nil {
		return nil, fmt.Errorf("list memories: %w", err)
	}

	r := &CollectedReport{}

	// Build a present-set.
	present := map[string]string{} // name -> body
	for _, m := range list.Memories {
		if len(opts.Memories) > 0 && !containsStr(opts.Memories, m.Name) {
			continue
		}
		present[m.Name] = m.Content
		r.PresentMemories = append(r.PresentMemories, m.Name)
	}
	sort.Strings(r.PresentMemories)

	// Compute expected memories from agent applicability.
	expected := map[string][]string{} // memName -> []agentName
	if p != nil && p.Config != nil {
		for _, ag := range agent.GetBuiltinAgents() {
			if !project.ApplicabilityMatches(ag.Applicability, p.Config.Classification) {
				continue
			}
			for _, m := range ag.ContextMemories {
				expected[m] = append(expected[m], ag.Name)
			}
		}
	}

	for memName, agents := range expected {
		if _, ok := present[memName]; !ok {
			r.MissingExpected = append(r.MissingExpected, MissingMemory{
				Name:             memName,
				ExpectedByAgents: agents,
			})
		}
	}
	sort.Slice(r.MissingExpected, func(i, j int) bool {
		return r.MissingExpected[i].Name < r.MissingExpected[j].Name
	})

	// Cross-references: scan each memory body for occurrences of other
	// memory names (word-boundary, case-insensitive).
	for fromName, body := range present {
		bodyLower := strings.ToLower(body)
		for toName := range present {
			if toName == fromName {
				continue
			}
			if strings.Contains(bodyLower, strings.ToLower(toName)) {
				r.CrossReferences = append(r.CrossReferences, CrossReference{From: fromName, To: toName})
			}
		}
	}
	sort.Slice(r.CrossReferences, func(i, j int) bool {
		if r.CrossReferences[i].From != r.CrossReferences[j].From {
			return r.CrossReferences[i].From < r.CrossReferences[j].From
		}
		return r.CrossReferences[i].To < r.CrossReferences[j].To
	})

	// Orphan memories: present, not expected, and never referenced.
	referenced := map[string]bool{}
	for _, xr := range r.CrossReferences {
		referenced[xr.To] = true
	}
	for memName := range present {
		if _, isExpected := expected[memName]; isExpected {
			continue
		}
		if referenced[memName] {
			continue
		}
		r.OrphanMemories = append(r.OrphanMemories, memName)
	}
	sort.Strings(r.OrphanMemories)

	if len(r.PresentMemories) == 0 {
		r.Notes = append(r.Notes, "no memories present")
	}
	if len(expected) == 0 {
		r.Notes = append(r.Notes, "no expected memories computed (project may be unclassified)")
	}

	return r, nil
}

// RenderCollectedText renders a text view.
func RenderCollectedText(r *CollectedReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Collected-Context Audit\n\n")
	fmt.Fprintf(&b, "Present memories (%d): %s\n\n", len(r.PresentMemories), strings.Join(r.PresentMemories, ", "))

	if len(r.MissingExpected) > 0 {
		fmt.Fprintf(&b, "### Missing (expected by agents):\n")
		for _, m := range r.MissingExpected {
			fmt.Fprintf(&b, "  - %s  (expected by: %s)\n", m.Name, strings.Join(m.ExpectedByAgents, ", "))
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(r.CrossReferences) > 0 {
		fmt.Fprintf(&b, "### Cross-references:\n")
		for _, xr := range r.CrossReferences {
			fmt.Fprintf(&b, "  - %s -> %s\n", xr.From, xr.To)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(r.OrphanMemories) > 0 {
		fmt.Fprintf(&b, "### Orphan memories (not expected, not cross-referenced):\n")
		for _, m := range r.OrphanMemories {
			fmt.Fprintf(&b, "  - %s\n", m)
		}
		fmt.Fprintf(&b, "\n")
	}

	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
