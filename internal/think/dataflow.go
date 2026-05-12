package think

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ihavespoons/zrok/internal/finding"
	"github.com/ihavespoons/zrok/internal/navigate"
	"github.com/ihavespoons/zrok/internal/project"
)

// DataflowOptions configures dataflow analysis.
type DataflowOptions struct {
	// Source is a regex/literal pattern locating untrusted-data origins.
	Source string
	// Sink is a regex/literal pattern locating security-sensitive operations.
	Sink string
	// File limits analysis to a single file (project-relative path).
	File string
	// FromFinding loads source/sink from an existing finding (FIND-XXX).
	FromFinding string
	// MaxChains caps reported chains per file (default 8).
	MaxChains int
}

// DataflowChain represents one source-to-sink trace within a single file.
type DataflowChain struct {
	File        string         `json:"file"`
	SourceLine  int            `json:"source_line"`
	SourceCode  string         `json:"source_code"`
	SinkLine    int            `json:"sink_line"`
	SinkCode    string         `json:"sink_code"`
	Assignments []FlowStep     `json:"assignments,omitempty"`
	Guards      []FlowStep     `json:"guards,omitempty"`
	Verdict     string         `json:"verdict"` // "unguarded" | "guarded" | "guard-uncertain"
	Confidence  string         `json:"confidence"`
	Reasoning   string         `json:"reasoning"`
}

// FlowStep is one intermediate line between source and sink.
type FlowStep struct {
	Line     int    `json:"line"`
	Code     string `json:"code"`
	Variable string `json:"variable,omitempty"`
	Kind     string `json:"kind,omitempty"` // "assignment" | "guard"
}

// DataflowReport is the structured result of a dataflow analysis.
type DataflowReport struct {
	Source       string          `json:"source"`
	Sink         string          `json:"sink"`
	File         string          `json:"file,omitempty"`
	FromFinding  string          `json:"from_finding,omitempty"`
	FilesScanned int             `json:"files_scanned"`
	Chains       []DataflowChain `json:"chains"`
	Notes        []string        `json:"notes,omitempty"`
}

// guardPatterns lists call-name fragments that indicate a defensive guard
// between a source and sink. The list draws from the OWASP-subset fixture's
// guard_style.yaml memory and common Python/Go web-stack defenses.
//
// Each alternative is required to be followed by `(` (a call shape), `.` (a
// member access), or `\b` for the few patterns that aren't calls (e.g.
// `in ` collection-membership tests). This avoids false hits on string
// literals like `'safe!'`.
var guardPatterns = regexp.MustCompile(
	`(?i)(` +
		// bare or qualified function/method calls (allow optional ".method"
		// after the keyword to catch e.g. bleach.clean, shlex.quote)
		`\b(validate|sanitize|escape|safe_load|allowlist|whitelist|` +
		`urlparse|urlsplit|literal_eval|bleach|secure_filename|` +
		`fullmatch|isalnum|isdigit|shlex|startswith|endswith)` +
		`(\.[A-Za-z_]+)?\s*\(|` +
		// other qualified calls
		`\b(html\.escape|re\.match|re\.fullmatch|ast\.literal_eval)\s*\(|` +
		// parameterized SQL hint
		`\bparameteriz|` +
		// in (...) / in [...] containment tests
		`\bin\s*[\(\[]` +
		`)`)

// assignmentRE matches a simple python/JS-ish variable assignment.
var assignmentRE = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z_0-9]*)\s*=[^=]`)

// AnalyzeDataflow performs an intra-file source-to-sink trace across the
// project (or a single file). It is intentionally simple: regex-based,
// linear within each file, and reports guards observed between the source
// and sink lines.
func AnalyzeDataflow(p *project.Project, opts DataflowOptions) (*DataflowReport, error) {
	if opts.MaxChains <= 0 {
		opts.MaxChains = 8
	}

	// If a finding is named, hydrate source/sink/file from it.
	if opts.FromFinding != "" {
		store := finding.NewStore(p)
		f, err := store.Read(opts.FromFinding)
		if err != nil {
			return nil, fmt.Errorf("from-finding: %w", err)
		}
		if opts.File == "" {
			opts.File = f.Location.File
		}
		if opts.Source == "" {
			opts.Source = inferSourceFromFinding(f)
		}
		if opts.Sink == "" {
			opts.Sink = inferSinkFromFinding(f)
		}
	}

	if opts.Source == "" || opts.Sink == "" {
		return nil, fmt.Errorf("source and sink patterns are required (use --source/--sink or --from-finding)")
	}

	report := &DataflowReport{
		Source:      opts.Source,
		Sink:        opts.Sink,
		File:        opts.File,
		FromFinding: opts.FromFinding,
	}

	srcRE, err := regexp.Compile("(?i)" + opts.Source)
	if err != nil {
		return nil, fmt.Errorf("invalid source pattern: %w", err)
	}
	sinkRE, err := regexp.Compile("(?i)" + opts.Sink)
	if err != nil {
		return nil, fmt.Errorf("invalid sink pattern: %w", err)
	}

	// Collect files to analyze.
	var files []string
	if opts.File != "" {
		files = []string{opts.File}
	} else {
		// Use Finder to locate files containing either pattern.
		f := navigate.NewFinder(p)
		sourceMatches, err := f.Search(opts.Source, &navigate.SearchOptions{Regex: true, MaxResults: 5000})
		if err != nil {
			return nil, fmt.Errorf("search source: %w", err)
		}
		sinkMatches, err := f.Search(opts.Sink, &navigate.SearchOptions{Regex: true, MaxResults: 5000})
		if err != nil {
			return nil, fmt.Errorf("search sink: %w", err)
		}
		srcFiles := uniqueFiles(sourceMatches.Matches)
		sinkFiles := uniqueFiles(sinkMatches.Matches)
		for path := range srcFiles {
			if sinkFiles[path] {
				files = append(files, path)
			}
		}
		sort.Strings(files)
	}

	report.FilesScanned = len(files)
	if len(files) == 0 {
		report.Notes = append(report.Notes, "no file contains both source and sink patterns")
		return report, nil
	}

	for _, relPath := range files {
		fullPath := relPath
		if !filepath.IsAbs(fullPath) {
			fullPath = filepath.Join(p.RootPath, relPath)
		}
		chains, err := traceFile(fullPath, relPath, srcRE, sinkRE, opts.MaxChains)
		if err != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("%s: %v", relPath, err))
			continue
		}
		report.Chains = append(report.Chains, chains...)
	}

	return report, nil
}

// traceFile walks one file and emits chains pairing each source occurrence
// with the next sink occurrence after it.
func traceFile(fullPath, relPath string, srcRE, sinkRE *regexp.Regexp, maxChains int) ([]DataflowChain, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var srcLines, sinkLines []int
	for i, line := range lines {
		if srcRE.MatchString(line) {
			srcLines = append(srcLines, i)
		}
		if sinkRE.MatchString(line) {
			sinkLines = append(sinkLines, i)
		}
	}

	var chains []DataflowChain
	for _, srcIdx := range srcLines {
		// Find the closest sink after this source.
		sinkIdx := -1
		for _, s := range sinkLines {
			if s > srcIdx {
				sinkIdx = s
				break
			}
		}
		if sinkIdx == -1 {
			continue
		}

		chain := DataflowChain{
			File:       relPath,
			SourceLine: srcIdx + 1,
			SourceCode: strings.TrimSpace(lines[srcIdx]),
			SinkLine:   sinkIdx + 1,
			SinkCode:   strings.TrimSpace(lines[sinkIdx]),
		}

		// Walk lines between source (exclusive) and sink (exclusive),
		// recording assignments and guard-like calls.
		for j := srcIdx + 1; j < sinkIdx; j++ {
			ln := lines[j]
			trimmed := strings.TrimSpace(ln)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if m := assignmentRE.FindStringSubmatch(ln); m != nil {
				chain.Assignments = append(chain.Assignments, FlowStep{
					Line:     j + 1,
					Code:     trimmed,
					Variable: m[1],
					Kind:     "assignment",
				})
			}
			if guardPatterns.MatchString(ln) {
				chain.Guards = append(chain.Guards, FlowStep{
					Line: j + 1,
					Code: trimmed,
					Kind: "guard",
				})
			}
		}

		// Also check source and sink lines themselves for inline guards
		// (e.g. parameterized cur.execute(sql, params) — '?' placeholder
		// is hard to regex, but call-shape hints help).
		if guardPatterns.MatchString(lines[sinkIdx]) {
			chain.Guards = append(chain.Guards, FlowStep{
				Line: sinkIdx + 1,
				Code: strings.TrimSpace(lines[sinkIdx]),
				Kind: "guard",
			})
		}

		// Verdict.
		switch {
		case len(chain.Guards) == 0:
			chain.Verdict = "unguarded"
			chain.Confidence = "medium"
			chain.Reasoning = "no guard-like call found between source and sink"
		case len(chain.Guards) > 0 && containsEffectiveGuard(chain.Guards):
			chain.Verdict = "guarded"
			chain.Confidence = "low"
			chain.Reasoning = fmt.Sprintf("%d guard-like call(s) found; verify each is effective for this CWE", len(chain.Guards))
		default:
			chain.Verdict = "guard-uncertain"
			chain.Confidence = "low"
			chain.Reasoning = "guard-shaped calls present but effectiveness unclear; manual review needed"
		}

		chains = append(chains, chain)
		if len(chains) >= maxChains {
			break
		}
	}

	return chains, nil
}

// containsEffectiveGuard returns true if any guard looks substantive
// (validation, sanitization, parameterization) rather than a mere
// shape-check (startswith, endswith, isalnum).
func containsEffectiveGuard(guards []FlowStep) bool {
	strong := regexp.MustCompile(`(?i)(\b(validate|sanitize|escape|safe_load|allowlist|whitelist|bleach|html\.escape|shlex)\s*\(|\bparameteriz)`)
	for _, g := range guards {
		if strong.MatchString(g.Code) {
			return true
		}
	}
	return false
}

func uniqueFiles(matches []navigate.SearchMatch) map[string]bool {
	out := make(map[string]bool, len(matches))
	for _, m := range matches {
		out[m.File] = true
	}
	return out
}

// inferSourceFromFinding tries to extract a source pattern from a finding's
// description. We look for "SOURCE:" lines and fall back to common request-
// access hints.
func inferSourceFromFinding(f *finding.Finding) string {
	if pat := extractAfter(f.Description, "SOURCE:"); pat != "" {
		return regexCleanup(pat)
	}
	// Common Python/Flask hints.
	return `request\.(form|args|cookies|headers|json|values)\.get|request\.data`
}

// inferSinkFromFinding tries to extract a sink pattern from a finding's
// description. We look for "SINK:" lines and fall back to CWE-specific hints.
func inferSinkFromFinding(f *finding.Finding) string {
	if pat := extractAfter(f.Description, "SINK:"); pat != "" {
		return regexCleanup(pat)
	}
	// Fallback by CWE.
	switch strings.ToUpper(f.CWE) {
	case "CWE-89":
		return `cur\.execute|cursor\.execute|sqlalchemy\.text|db\.session\.execute`
	case "CWE-78":
		return `os\.system|subprocess\.|exec\.Command|child_process`
	case "CWE-94":
		return `\beval\(|\bexec\(|compile\(|Function\(`
	case "CWE-643":
		return `lxml\.etree\.XPath|elementpath\.select|\.xpath\(`
	case "CWE-79":
		return `render_template_string|Markup\(|\|safe\b|dangerouslySetInnerHTML`
	case "CWE-601":
		return `flask\.redirect|return\s+redirect`
	case "CWE-22":
		return `open\(|os\.path\.join|send_from_directory`
	}
	return `cur\.execute|os\.system|subprocess\.|\beval\(|\bexec\(`
}

// extractAfter returns the first non-empty token after the given label on
// any line that begins (after trim) with that label.
func extractAfter(text, label string) string {
	for _, ln := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, label) {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, label))
			// Take the first call-shape token, e.g. "cur.execute(sql)" -> "cur.execute".
			if idx := strings.IndexAny(rest, "( "); idx > 0 {
				rest = rest[:idx]
			}
			return rest
		}
	}
	return ""
}

// regexCleanup escapes common chars so an inferred call-name acts as a
// regex fragment.
func regexCleanup(s string) string {
	s = strings.TrimSpace(s)
	// Escape regex metacharacters that aren't useful in inferred patterns.
	specials := []string{`\`, `+`, `*`, `?`, `[`, `]`, `(`, `)`, `{`, `}`, `^`, `$`, `|`}
	for _, c := range specials {
		s = strings.ReplaceAll(s, c, `\`+c)
	}
	return s
}

// RenderDataflowText renders a human-friendly text view of the report.
func RenderDataflowText(r *DataflowReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Dataflow Analysis\n\n")
	fmt.Fprintf(&b, "Source pattern: %s\n", r.Source)
	fmt.Fprintf(&b, "Sink pattern:   %s\n", r.Sink)
	if r.File != "" {
		fmt.Fprintf(&b, "File:           %s\n", r.File)
	}
	if r.FromFinding != "" {
		fmt.Fprintf(&b, "From finding:   %s\n", r.FromFinding)
	}
	fmt.Fprintf(&b, "Files scanned:  %d\n", r.FilesScanned)
	fmt.Fprintf(&b, "Chains found:   %d\n\n", len(r.Chains))

	if len(r.Chains) == 0 {
		fmt.Fprintf(&b, "No source-to-sink chains found.\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  note: %s\n", n)
		}
		return b.String()
	}

	for i, c := range r.Chains {
		fmt.Fprintf(&b, "### Chain %d: %s\n", i+1, c.File)
		fmt.Fprintf(&b, "  SOURCE: line %d: %s\n", c.SourceLine, c.SourceCode)
		for _, a := range c.Assignments {
			fmt.Fprintf(&b, "    -> ASSIGN line %d (%s): %s\n", a.Line, a.Variable, a.Code)
		}
		for _, g := range c.Guards {
			fmt.Fprintf(&b, "    -> GUARD?  line %d: %s\n", g.Line, g.Code)
		}
		fmt.Fprintf(&b, "    -> SINK: line %d: %s\n", c.SinkLine, c.SinkCode)
		fmt.Fprintf(&b, "  VERDICT: %s (confidence: %s)\n", c.Verdict, c.Confidence)
		fmt.Fprintf(&b, "  REASONING: %s\n\n", c.Reasoning)
	}

	for _, n := range r.Notes {
		fmt.Fprintf(&b, "note: %s\n", n)
	}
	return b.String()
}
