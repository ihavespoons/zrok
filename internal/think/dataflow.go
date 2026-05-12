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
	// Sink is an explicit regex/literal pattern locating security-sensitive
	// operations. When non-empty it OVERRIDES SinkClasses and the default
	// sink set.
	Sink string
	// SinkClasses narrows the default sink mix to one or more named classes
	// (e.g. "deserialization", "xxe", "ldap"). Use `ListSinkClasses()` to
	// enumerate. Ignored when Sink is set.
	SinkClasses []string
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
	SinkClasses  []string        `json:"sink_classes,omitempty"`
	File         string          `json:"file,omitempty"`
	FromFinding  string          `json:"from_finding,omitempty"`
	FilesScanned int             `json:"files_scanned"`
	Chains       []DataflowChain `json:"chains"`
	Summary      DataflowSummary `json:"summary"`
	Notes        []string        `json:"notes,omitempty"`
}

// DataflowSummary tallies the chains found in a report by verdict.
type DataflowSummary struct {
	Sources    int `json:"sources"`
	Sinks      int `json:"sinks"`
	Chains     int `json:"chains"`
	Unguarded  int `json:"unguarded"`
	Guarded    int `json:"guarded"`
	Uncertain  int `json:"uncertain"`
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

	// Resolve the sink pattern when none was given explicitly.
	// Precedence: explicit Sink > named SinkClasses > default class mix.
	var unknownClasses []string
	resolvedClasses := opts.SinkClasses
	if opts.Sink == "" {
		var pat string
		pat, unknownClasses = BuildSinkPatternFromClasses(opts.SinkClasses)
		opts.Sink = pat
		if len(opts.SinkClasses) == 0 {
			resolvedClasses = DefaultSinkClasses()
		}
	}

	if opts.Source == "" || opts.Sink == "" {
		if len(unknownClasses) > 0 {
			return nil, fmt.Errorf("no valid sink classes resolved (unknown: %s); use --sink, --sink-class <name>, or --from-finding",
				strings.Join(unknownClasses, ", "))
		}
		return nil, fmt.Errorf("source and sink patterns are required (use --source/--sink or --from-finding)")
	}

	report := &DataflowReport{
		Source:      opts.Source,
		Sink:        opts.Sink,
		SinkClasses: resolvedClasses,
		File:        opts.File,
		FromFinding: opts.FromFinding,
	}
	for _, u := range unknownClasses {
		report.Notes = append(report.Notes, fmt.Sprintf("unknown sink class: %q (see ListSinkClasses)", u))
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
		chains, fileSrc, fileSink, err := traceFile(fullPath, relPath, srcRE, sinkRE, opts.MaxChains)
		if err != nil {
			report.Notes = append(report.Notes, fmt.Sprintf("%s: %v", relPath, err))
			continue
		}
		report.Chains = append(report.Chains, chains...)
		report.Summary.Sources += fileSrc
		report.Summary.Sinks += fileSink
	}

	for _, c := range report.Chains {
		switch c.Verdict {
		case "guarded":
			report.Summary.Guarded++
		case "guard-uncertain":
			report.Summary.Uncertain++
		default:
			report.Summary.Unguarded++
		}
	}
	report.Summary.Chains = len(report.Chains)

	return report, nil
}

// traceFile walks one file and emits chains pairing each source occurrence
// with the next sink occurrence after it. It also returns the total source
// and sink line counts seen in the file (after filtering imports), so the
// caller can populate report-level Summary tallies.
func traceFile(fullPath, relPath string, srcRE, sinkRE *regexp.Regexp, maxChains int) ([]DataflowChain, int, int, error) {
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, 0, err
	}

	var srcLines, sinkLines []int
	for i, line := range lines {
		// C2: skip import lines when selecting source/sink candidates.
		// `import X` and `from X import Y` are never the actual data-flow
		// site; matching them confuses callers who then re-read the file
		// to find the real call.
		if isImportLine(line) {
			continue
		}
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
		// (e.g. shlex.quote(arg) right in the call site).
		if guardPatterns.MatchString(lines[sinkIdx]) {
			chain.Guards = append(chain.Guards, FlowStep{
				Line: sinkIdx + 1,
				Code: strings.TrimSpace(lines[sinkIdx]),
				Kind: "guard",
			})
		}

		// C3: parameterized-call-at-sink detection. A sink call with >=2
		// top-level positional args is treated as guarded ("parameterized
		// call at sink"). A sink call with exactly 1 arg that contains an
		// f-string or string concatenation is treated as unguarded
		// regardless of other guard-shaped calls. Otherwise we fall back
		// to the legacy guard-list verdict.
		paramVerdict, paramReason := classifySinkArgs(lines[sinkIdx], sinkRE)
		switch paramVerdict {
		case "guarded":
			chain.Verdict = "guarded"
			chain.Confidence = "medium"
			chain.Reasoning = paramReason
			// Surface the sink line as a guard for transparency.
			chain.Guards = append(chain.Guards, FlowStep{
				Line: sinkIdx + 1,
				Code: strings.TrimSpace(lines[sinkIdx]),
				Kind: "guard",
			})
		case "unguarded":
			chain.Verdict = "unguarded"
			chain.Confidence = "high"
			chain.Reasoning = paramReason
		default:
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
		}

		chains = append(chains, chain)
		if len(chains) >= maxChains {
			break
		}
	}

	return chains, len(srcLines), len(sinkLines), nil
}

// isImportLine reports whether a line is a Python-style import statement
// (`import X` or `from X import Y`). Whitespace at the start is ignored.
func isImportLine(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "from ")
}

// sqlSinkRE recognizes SQL-execute-shaped sinks where a 2nd positional or
// keyword argument is the parameter-binding (the actual guard against SQLi).
// We use this to scope the "2+ args → guarded" heuristic. Non-SQL sinks
// (yaml.load(x, Loader=...), subprocess.run(cmd, shell=True),
// flask.redirect(url, code=302), etc.) naturally take kwargs and would be
// false-positive-guarded under a generic rule.
var sqlSinkRE = regexp.MustCompile(`(?i)\b(cur|cursor|conn|connection|db|session)\.execute(many)?\b|\bsqlalchemy\.text\b|\bsession\.execute\b`)

// classifySinkArgs inspects the sink line's argument list. It returns:
//
//   - "guarded", reason: when the sink call is SQL-shaped AND has >=2
//     top-level args (parameterized call at sink — binding is the guard).
//   - "unguarded", reason: when the sink call has exactly 1 top-level arg
//     and that arg is an f-string or contains string concatenation. This
//     rule applies to ALL sink classes (an f-string at any sink is a
//     definite injection signal).
//   - "", "": when the heuristic cannot decide; the caller should fall back
//     to legacy guard-list verdict.
//
// The "2+ args → guarded" branch is intentionally scoped to SQL sinks: many
// non-SQL APIs (yaml.load, subprocess.run, flask.redirect) take kwargs that
// have nothing to do with binding parameters, so a generic 2-arg rule would
// produce confident-but-wrong "guarded" verdicts. Known limitation: this
// heuristic does NOT introspect kwargs (e.g. `yaml.load(bar, Loader=...)`
// is treated as 1-arg-or-unknown rather than parameterized).
//
// Argument parsing walks the substring after the first `(` belonging to the
// sink call, counting commas at paren/bracket/brace depth 1 only, treating
// quoted strings (including triple-quoted) as opaque. This avoids miscounting
// commas inside f-strings or nested calls.
func classifySinkArgs(line string, sinkRE *regexp.Regexp) (string, string) {
	loc := sinkRE.FindStringIndex(line)
	if loc == nil {
		return "", ""
	}
	// Find the opening paren of the sink call (the first '(' at or after the
	// match end).
	rest := line[loc[1]:]
	openIdx := strings.Index(rest, "(")
	if openIdx < 0 {
		return "", ""
	}
	body, ok := extractCallBody(rest[openIdx:])
	if !ok {
		return "", ""
	}
	args := splitTopLevelArgs(body)
	// Drop trailing empty arg from a trailing comma.
	if n := len(args); n > 0 && strings.TrimSpace(args[n-1]) == "" {
		args = args[:n-1]
	}
	matchedSnippet := line[loc[0]:loc[1]]
	isSQL := sqlSinkRE.MatchString(matchedSnippet)
	if isSQL && len(args) >= 2 {
		return "guarded", "parameterized call at sink (>=2 args; binding is the guard)"
	}
	if len(args) == 1 {
		arg := args[0]
		if looksLikeFString(arg) || hasStringConcat(arg) {
			return "unguarded", "sink called with a single concatenated/f-string argument"
		}
	}
	return "", ""
}

// extractCallBody takes a substring starting at '(' and returns the contents
// between that paren and its matching ')'. It tracks string literals so
// embedded parens inside quotes don't confuse depth tracking. The second
// result is false when no matching ')' is found on this line (likely a
// multi-line call; we conservatively decline to classify).
func extractCallBody(s string) (string, bool) {
	if len(s) == 0 || s[0] != '(' {
		return "", false
	}
	depth := 0
	var i int
	for i = 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[1:i], true
			}
		case '"', '\'':
			// Skip string literal. Supports triple-quoted forms.
			end := skipStringLiteral(s, i)
			if end < 0 {
				return "", false
			}
			i = end
		}
	}
	return "", false
}

// skipStringLiteral returns the index of the closing quote, or -1 if the
// string is unterminated on this line. Handles triple-quoted strings and
// simple backslash escapes inside single-line strings.
func skipStringLiteral(s string, start int) int {
	if start >= len(s) {
		return -1
	}
	q := s[start]
	// Triple-quoted?
	if start+2 < len(s) && s[start+1] == q && s[start+2] == q {
		i := start + 3
		for i+2 < len(s) {
			if s[i] == q && s[i+1] == q && s[i+2] == q {
				return i + 2
			}
			i++
		}
		return -1
	}
	for i := start + 1; i < len(s); i++ {
		if s[i] == '\\' { // escape
			i++
			continue
		}
		if s[i] == q {
			return i
		}
	}
	return -1
}

// splitTopLevelArgs splits a comma-separated argument list at depth-0 commas
// only. Parens, brackets, and braces increase depth; string literals are
// treated as opaque.
func splitTopLevelArgs(body string) []string {
	var args []string
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '"', '\'':
			end := skipStringLiteral(body, i)
			if end < 0 {
				// Unterminated; treat rest as one arg fragment.
				return append(args, body[start:])
			}
			i = end
		case ',':
			if depth == 0 {
				args = append(args, body[start:i])
				start = i + 1
			}
		}
	}
	args = append(args, body[start:])
	return args
}

// looksLikeFString returns true if the arg starts with an f-string prefix
// (Python f"..." / f'...' / rf"..." / fr'...').
func looksLikeFString(arg string) bool {
	t := strings.TrimSpace(arg)
	if len(t) < 2 {
		return false
	}
	// Strip leading prefix characters (f, r, b, u, in any order).
	lower := strings.ToLower(t)
	prefixEnd := 0
	for prefixEnd < len(lower) && strings.ContainsRune("frbu", rune(lower[prefixEnd])) {
		prefixEnd++
		if prefixEnd > 3 {
			break
		}
	}
	if prefixEnd == 0 || prefixEnd >= len(t) {
		return false
	}
	if t[prefixEnd] != '"' && t[prefixEnd] != '\'' {
		return false
	}
	// Must contain an 'f' in the prefix to qualify as an f-string.
	return strings.ContainsAny(lower[:prefixEnd], "f")
}

// hasStringConcat returns true if the arg contains a top-level `+` outside
// of string literals. This is a heuristic for `"prefix " + user_var`.
func hasStringConcat(arg string) bool {
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		if c == '"' || c == '\'' {
			end := skipStringLiteral(arg, i)
			if end < 0 {
				return false
			}
			i = end
			continue
		}
		if c == '+' {
			return true
		}
	}
	return false
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
// When no CWE-specific class is known, we return the default sink mix so
// callers running `--from-finding` get reasonable coverage out of the box.
func inferSinkFromFinding(f *finding.Finding) string {
	if pat := extractAfter(f.Description, "SINK:"); pat != "" {
		return regexCleanup(pat)
	}
	// Fallback by CWE — reuse the named sink classes so additions there
	// (e.g. new deserialization formats) automatically flow through.
	cweToClass := map[string]string{
		"CWE-89":  "sqli",
		"CWE-78":  "cmdi",
		"CWE-94":  "codeexec",
		"CWE-502": "deserialization",
		"CWE-611": "xxe",
		"CWE-643": "xpath",
		"CWE-90":  "ldap",
		"CWE-79":  "xss",
		"CWE-601": "redirect",
		"CWE-22":  "pathtrav",
	}
	if cls, ok := cweToClass[strings.ToUpper(f.CWE)]; ok {
		if pat := SinkClassPattern(cls); pat != "" {
			return pat
		}
	}
	return DefaultSinkPattern()
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
	// Summary first so callers piping to less|head see the headline.
	fmt.Fprintf(&b, "Summary: %d sources, %d sinks, %d chains (%d unguarded / %d guarded / %d uncertain)\n\n",
		r.Summary.Sources, r.Summary.Sinks, r.Summary.Chains,
		r.Summary.Unguarded, r.Summary.Guarded, r.Summary.Uncertain)
	fmt.Fprintf(&b, "Source pattern: %s\n", r.Source)
	fmt.Fprintf(&b, "Sink pattern:   %s\n", r.Sink)
	if len(r.SinkClasses) > 0 {
		fmt.Fprintf(&b, "Sink classes:   %s\n", strings.Join(r.SinkClasses, ", "))
	}
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
