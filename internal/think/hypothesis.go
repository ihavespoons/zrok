package think

import (
	"fmt"
	"sort"
	"strings"

	"github.com/diffsec/quokka/internal/agent"
	"github.com/diffsec/quokka/internal/memory"
	"github.com/diffsec/quokka/internal/project"
)

// HypothesisOptions configures hypothesis generation.
type HypothesisOptions struct {
	// Memories lists memory names to include as context. If empty, all
	// memories are scanned.
	Memories []string
	// Tech is an optional override for tech-stack hints (otherwise read
	// from project config + tech_stack memory).
	Tech []string
	// MaxHypotheses caps the output list (default 10).
	MaxHypotheses int
}

// Hypothesis is one ranked, testable security hypothesis.
type Hypothesis struct {
	Rank        int      `json:"rank"`
	CWE         string   `json:"cwe"`
	Name        string   `json:"name"`
	Rationale   string   `json:"rationale"`
	Evidence    []string `json:"evidence,omitempty"`
	SinkPattern string   `json:"sink_pattern,omitempty"`
	Test        string   `json:"test"`
	Score       int      `json:"score"`
}

// HypothesisReport is the structured result.
type HypothesisReport struct {
	TechHints        []string     `json:"tech_hints,omitempty"`
	MemoriesScanned  []string     `json:"memories_scanned"`
	Hypotheses       []Hypothesis `json:"hypotheses"`
	Notes            []string     `json:"notes,omitempty"`
}

// cweSinkMap maps CWE IDs to a (name, sink regex, evidence keywords).
type cweEntry struct {
	Name     string
	SinkRE   string
	Keywords []string // memory text triggers
}

var cweSinkMap = map[string]cweEntry{
	"CWE-89":  {"SQL Injection", `cur\.execute|cursor\.execute|sqlalchemy\.text|db\.session\.execute`, []string{"sql", "sqlite", "sqlalchemy", "cursor", "execute"}},
	"CWE-78":  {"OS Command Injection", `os\.system|subprocess\.|exec\.Command|child_process`, []string{"subprocess", "os.system", "shell", "command"}},
	"CWE-94":  {"Code Injection", `\beval\(|\bexec\(|compile\(|Function\(`, []string{"eval", "exec", "compile"}},
	"CWE-643": {"XPath Injection", `lxml\.etree\.XPath|elementpath\.select|\.xpath\(`, []string{"xpath", "lxml", "elementpath"}},
	"CWE-79":  {"XSS", `render_template_string|Markup\(|\|safe\b|dangerouslySetInnerHTML`, []string{"template", "markup", "safe", "render_template"}},
	"CWE-601": {"Open Redirect", `flask\.redirect|return\s+redirect`, []string{"redirect", "url_for"}},
	"CWE-22":  {"Path Traversal", `open\(|os\.path\.join|send_from_directory`, []string{"path", "open", "filename"}},
	"CWE-611": {"XXE", `etree\.parse|XMLParser|fromstring`, []string{"xml", "lxml", "etree"}},
	"CWE-502": {"Unsafe Deserialization", `pickle\.loads|yaml\.load|marshal\.loads`, []string{"pickle", "yaml.load", "deserialize"}},
	"CWE-327": {"Broken Crypto", `hashlib\.md5|hashlib\.sha1|DES`, []string{"md5", "sha1", "des"}},
	"CWE-338": {"Weak RNG", `random\.\w+\(`, []string{"random.", "mersenne", "randint"}},
	"CWE-798": {"Hardcoded Credentials", `secret_key\s*=|password\s*=\s*['\"]`, []string{"secret_key", "password", "hardcoded"}},
}

// AnalyzeHypothesis generates ranked CWE hypotheses from memory + tech stack.
func AnalyzeHypothesis(p *project.Project, opts HypothesisOptions) (*HypothesisReport, error) {
	if opts.MaxHypotheses <= 0 {
		opts.MaxHypotheses = 10
	}

	report := &HypothesisReport{}

	// Gather tech hints.
	if len(opts.Tech) > 0 {
		report.TechHints = opts.Tech
	} else if p != nil && p.Config != nil {
		for _, lang := range p.Config.TechStack.Languages {
			report.TechHints = append(report.TechHints, lang.Name)
			report.TechHints = append(report.TechHints, lang.Frameworks...)
		}
		report.TechHints = append(report.TechHints, p.Config.TechStack.Databases...)
		report.TechHints = append(report.TechHints, p.Config.TechStack.Auth...)
	}

	// Load memories.
	memStore := memory.NewStore(p)
	defer func() { _ = memStore.Close() }()

	var memContents []memContent
	if len(opts.Memories) == 0 {
		list, err := memStore.List("")
		if err != nil {
			return nil, fmt.Errorf("list memories: %w", err)
		}
		for _, m := range list.Memories {
			memContents = append(memContents, memContent{Name: m.Name, Body: m.Content})
			report.MemoriesScanned = append(report.MemoriesScanned, m.Name)
		}
	} else {
		for _, name := range opts.Memories {
			m, err := memStore.ReadByName(name)
			if err != nil {
				report.Notes = append(report.Notes, fmt.Sprintf("memory %q: %v", name, err))
				continue
			}
			memContents = append(memContents, memContent{Name: m.Name, Body: m.Content})
			report.MemoriesScanned = append(report.MemoriesScanned, m.Name)
		}
	}

	// Determine relevant CWEs from agent applicability + project classification.
	var relevantCWEs []string
	if p != nil && p.Config != nil {
		seen := map[string]bool{}
		for _, ag := range agent.GetBuiltinAgents() {
			if !project.ApplicabilityMatches(ag.Applicability, p.Config.Classification) {
				continue
			}
			for _, c := range ag.CWEChecklist {
				if !seen[c.ID] {
					relevantCWEs = append(relevantCWEs, c.ID)
					seen[c.ID] = true
				}
			}
		}
	}
	// If we couldn't classify, fall back to all known CWEs.
	if len(relevantCWEs) == 0 {
		for id := range cweSinkMap {
			relevantCWEs = append(relevantCWEs, id)
		}
	}
	sort.Strings(relevantCWEs)

	// Score each CWE by how many tech hints + memory keywords match.
	techJoined := strings.ToLower(strings.Join(report.TechHints, " "))
	for _, cweID := range relevantCWEs {
		entry, ok := cweSinkMap[cweID]
		if !ok {
			continue
		}

		score := 0
		var evidence []string
		// Tech-stack hits.
		for _, kw := range entry.Keywords {
			if strings.Contains(techJoined, strings.ToLower(kw)) {
				score += 2
				evidence = append(evidence, fmt.Sprintf("tech mentions %q", kw))
			}
		}
		// Memory-content hits.
		for _, mc := range memContents {
			body := strings.ToLower(mc.Body)
			for _, kw := range entry.Keywords {
				if strings.Contains(body, strings.ToLower(kw)) {
					score += 1
					evidence = append(evidence, fmt.Sprintf("%s mentions %q", mc.Name, kw))
					break
				}
			}
		}
		if score == 0 {
			continue
		}

		rationale := buildRationale(entry, report.TechHints, evidence)
		test := fmt.Sprintf(`quokka think dataflow --source "request\\.(form|args|cookies)\\.get" --sink "%s"`, entry.SinkRE)

		// Dedup evidence.
		evidence = dedup(evidence)

		report.Hypotheses = append(report.Hypotheses, Hypothesis{
			CWE:         cweID,
			Name:        entry.Name,
			Rationale:   rationale,
			Evidence:    evidence,
			SinkPattern: entry.SinkRE,
			Test:        test,
			Score:       score,
		})
	}

	// Rank by score desc.
	sort.SliceStable(report.Hypotheses, func(i, j int) bool {
		return report.Hypotheses[i].Score > report.Hypotheses[j].Score
	})
	if len(report.Hypotheses) > opts.MaxHypotheses {
		report.Hypotheses = report.Hypotheses[:opts.MaxHypotheses]
	}
	for i := range report.Hypotheses {
		report.Hypotheses[i].Rank = i + 1
	}

	return report, nil
}

type memContent struct {
	Name string
	Body string
}

func buildRationale(e cweEntry, tech []string, evidence []string) string {
	if len(tech) == 0 && len(evidence) == 0 {
		return fmt.Sprintf("Generic %s risk for the project.", e.Name)
	}
	return fmt.Sprintf("Tech/memory signals match %s sinks (%s).", e.Name, e.SinkRE)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// RenderHypothesisText returns a human-readable form of the report.
func RenderHypothesisText(r *HypothesisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Hypothesis Report\n\n")
	if len(r.TechHints) > 0 {
		fmt.Fprintf(&b, "Tech hints: %s\n", strings.Join(r.TechHints, ", "))
	}
	fmt.Fprintf(&b, "Memories scanned: %d\n\n", len(r.MemoriesScanned))

	if len(r.Hypotheses) == 0 {
		fmt.Fprintf(&b, "No hypotheses scored above zero. Check that memories or tech-stack hints reference known sink keywords.\n")
		return b.String()
	}

	for _, h := range r.Hypotheses {
		fmt.Fprintf(&b, "%d. %s — %s  (score %d)\n", h.Rank, h.CWE, h.Name, h.Score)
		fmt.Fprintf(&b, "   rationale: %s\n", h.Rationale)
		if len(h.Evidence) > 0 {
			fmt.Fprintf(&b, "   evidence:  %s\n", strings.Join(h.Evidence, "; "))
		}
		if h.SinkPattern != "" {
			fmt.Fprintf(&b, "   sink regex: %s\n", h.SinkPattern)
		}
		fmt.Fprintf(&b, "   test:      %s\n\n", h.Test)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}

