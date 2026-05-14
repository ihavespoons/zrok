package think

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ihavespoons/quokka/internal/finding"
	"github.com/ihavespoons/quokka/internal/navigate"
	"github.com/ihavespoons/quokka/internal/project"
)

// ValidateOptions configures a finding-validation analysis.
type ValidateOptions struct {
	// FindingID is the FIND-XXX identifier.
	FindingID string
	// ContextLines controls how many lines of code context around the
	// reported line are loaded (default 10).
	ContextLines int
}

// ValidateReport is the structured result of validating a finding.
type ValidateReport struct {
	FindingID    string         `json:"finding_id"`
	Title        string         `json:"title"`
	Severity     string         `json:"severity"`
	CWE          string         `json:"cwe"`
	Status       string         `json:"status"`
	Location     string         `json:"location"`
	CodeContext  []CodeLine     `json:"code_context"`
	SourceFound  bool           `json:"source_found"`
	SourceLines  []int          `json:"source_lines,omitempty"`
	SinkFound    bool           `json:"sink_found"`
	SinkLines    []int          `json:"sink_lines,omitempty"`
	GuardsFound  []FlowStep     `json:"guards_found,omitempty"`
	Verdict      string         `json:"verdict"`
	Confidence   string         `json:"confidence"`
	Rubric       []RubricCheck  `json:"rubric"`
	Notes        []string       `json:"notes,omitempty"`
}

// CodeLine is one line of context with metadata.
type CodeLine struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	IsFocus bool   `json:"is_focus,omitempty"`
}

// RubricCheck is a single boolean check in the validation rubric.
type RubricCheck struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// AnalyzeValidate validates a finding by reading the cited code, checking
// for source/sink patterns inferred from the description and CWE, and
// detecting any guard-like calls in the local context.
func AnalyzeValidate(p *project.Project, opts ValidateOptions) (*ValidateReport, error) {
	if opts.ContextLines <= 0 {
		opts.ContextLines = 10
	}

	store := finding.NewStore(p)
	f, err := store.Read(opts.FindingID)
	if err != nil {
		return nil, err
	}

	r := &ValidateReport{
		FindingID: f.ID,
		Title:     f.Title,
		Severity:  string(f.Severity),
		CWE:       f.CWE,
		Status:    string(f.Status),
		Location:  fmt.Sprintf("%s:%d", f.Location.File, f.Location.LineStart),
	}

	// Read code context around the cited line.
	reader := navigate.NewReader(p)
	rr, err := reader.ReadContext(f.Location.File, f.Location.LineStart, opts.ContextLines)
	if err != nil {
		r.Notes = append(r.Notes, fmt.Sprintf("could not read %s: %v", f.Location.File, err))
	} else {
		for i, ln := range rr.Lines {
			lineNo := rr.StartLine + i
			r.CodeContext = append(r.CodeContext, CodeLine{
				Line:    lineNo,
				Code:    ln,
				IsFocus: lineNo == f.Location.LineStart,
			})
		}
	}

	// Search the file for source and sink patterns inferred from finding.
	srcPat := inferSourceFromFinding(f)
	sinkPat := inferSinkFromFinding(f)

	if srcPat != "" {
		hits, lines := scanFileForPattern(reader, f.Location.File, srcPat)
		r.SourceFound = hits
		r.SourceLines = lines
	}
	if sinkPat != "" {
		hits, lines := scanFileForPattern(reader, f.Location.File, sinkPat)
		r.SinkFound = hits
		r.SinkLines = lines
	}

	// Detect guards anywhere in the file between any source and any sink.
	guards := findGuardsBetween(reader, f.Location.File, r.SourceLines, r.SinkLines)
	r.GuardsFound = guards

	// Build rubric.
	r.Rubric = []RubricCheck{
		{
			Name:   "code_readable",
			Pass:   len(r.CodeContext) > 0,
			Detail: fmt.Sprintf("%d lines of context loaded", len(r.CodeContext)),
		},
		{
			Name:   "source_pattern_present",
			Pass:   r.SourceFound,
			Detail: fmt.Sprintf("pattern: %s -> %d match(es)", srcPat, len(r.SourceLines)),
		},
		{
			Name:   "sink_pattern_present",
			Pass:   r.SinkFound,
			Detail: fmt.Sprintf("pattern: %s -> %d match(es)", sinkPat, len(r.SinkLines)),
		},
		{
			Name:   "no_guard_between",
			Pass:   len(r.GuardsFound) == 0,
			Detail: fmt.Sprintf("%d guard-like call(s) found", len(r.GuardsFound)),
		},
	}

	// Verdict & confidence.
	switch {
	case r.SourceFound && r.SinkFound && len(r.GuardsFound) == 0:
		r.Verdict = "likely_true_positive"
		r.Confidence = "high"
	case r.SourceFound && r.SinkFound && len(r.GuardsFound) > 0:
		r.Verdict = "uncertain_guard_present"
		r.Confidence = "medium"
	case r.SinkFound && !r.SourceFound:
		r.Verdict = "sink_present_source_missing"
		r.Confidence = "low"
	case !r.SinkFound:
		r.Verdict = "sink_missing"
		r.Confidence = "low"
	default:
		r.Verdict = "inconclusive"
		r.Confidence = "low"
	}

	return r, nil
}

func scanFileForPattern(r *navigate.Reader, path, pattern string) (bool, []int) {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return false, nil
	}
	rr, err := r.Read(path)
	if err != nil {
		return false, nil
	}
	var hits []int
	for i, ln := range rr.Lines {
		if re.MatchString(ln) {
			hits = append(hits, i+1)
		}
	}
	return len(hits) > 0, hits
}

func findGuardsBetween(r *navigate.Reader, path string, sources, sinks []int) []FlowStep {
	if len(sources) == 0 || len(sinks) == 0 {
		return nil
	}
	rr, err := r.Read(path)
	if err != nil {
		return nil
	}

	// Build a window covering each (src, next-sink) pair.
	type window struct{ lo, hi int }
	var windows []window
	for _, s := range sources {
		pick := -1
		for _, sk := range sinks {
			if sk > s {
				pick = sk
				break
			}
		}
		if pick > 0 {
			windows = append(windows, window{lo: s, hi: pick})
		}
	}

	var out []FlowStep
	seen := map[int]bool{}
	for _, w := range windows {
		for ln := w.lo + 1; ln < w.hi; ln++ {
			if seen[ln] {
				continue
			}
			if ln-1 < 0 || ln-1 >= len(rr.Lines) {
				continue
			}
			code := rr.Lines[ln-1]
			if guardPatterns.MatchString(code) {
				out = append(out, FlowStep{
					Line: ln,
					Code: strings.TrimSpace(code),
					Kind: "guard",
				})
				seen[ln] = true
			}
		}
	}
	return out
}

// RenderValidateText renders a human-friendly text view of the report.
func RenderValidateText(r *ValidateReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Validation Report: %s\n\n", r.FindingID)
	fmt.Fprintf(&b, "Title:    %s\n", r.Title)
	fmt.Fprintf(&b, "CWE:      %s\n", r.CWE)
	fmt.Fprintf(&b, "Severity: %s\n", r.Severity)
	fmt.Fprintf(&b, "Status:   %s\n", r.Status)
	fmt.Fprintf(&b, "Location: %s\n\n", r.Location)

	fmt.Fprintf(&b, "### Code Context\n")
	for _, cl := range r.CodeContext {
		marker := "  "
		if cl.IsFocus {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%4d: %s\n", marker, cl.Line, cl.Code)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "### Pattern Check\n")
	fmt.Fprintf(&b, "  source pattern matched: %v at lines %v\n", r.SourceFound, r.SourceLines)
	fmt.Fprintf(&b, "  sink pattern matched:   %v at lines %v\n", r.SinkFound, r.SinkLines)
	fmt.Fprintf(&b, "  guards between:         %d\n", len(r.GuardsFound))
	for _, g := range r.GuardsFound {
		fmt.Fprintf(&b, "    - line %d: %s\n", g.Line, g.Code)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "### Rubric\n")
	for _, c := range r.Rubric {
		mark := "FAIL"
		if c.Pass {
			mark = "PASS"
		}
		fmt.Fprintf(&b, "  [%s] %s — %s\n", mark, c.Name, c.Detail)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "### Verdict\n")
	fmt.Fprintf(&b, "  %s (confidence: %s)\n", r.Verdict, r.Confidence)

	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}
