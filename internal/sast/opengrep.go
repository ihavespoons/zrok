package sast

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ihavespoons/zrok/internal/finding"
)

// Scanner runs opengrep against a project and converts its SARIF output into
// zrok findings. The scanner itself doesn't write to the store — callers
// decide what to do with the results, which makes it easy to apply diff
// scoping or dedup before persisting.
type Scanner struct {
	// Binary is the opengrep executable path. Defaults to "opengrep" via PATH.
	Binary string

	// Config is the --config argument: a local rules directory, a single
	// rules YAML, or a registry shorthand like "p/security-audit". Required.
	Config string

	// ExtraConfigs are additional --config arguments appended after Config.
	// Used by cmd/sast.go to merge in project-local rules from .zrok/rules/
	// alongside the user's chosen ruleset, so org-specific rules apply
	// automatically without users re-specifying them.
	ExtraConfigs []string

	// ExtraArgs are passed through to opengrep scan, after the standard
	// SARIF + quiet flags. Use sparingly — most behavior should be exposed
	// via dedicated fields.
	ExtraArgs []string

	// ProjectRoot is used to relativize the file paths opengrep emits.
	// Opengrep SARIF output contains absolute paths (e.g. /tmp/repo-xyz/
	// src/api/users.py); without this, downstream finding matching,
	// fingerprinting, and SARIF code-scanning ingest see a path that
	// differs across runs from different working directories. Empty
	// means "leave paths as-is" — preserves the old behavior for callers
	// that don't yet plumb this through.
	ProjectRoot string
}

// Scan runs opengrep over the given target paths (files or directories) and
// returns the parsed findings. Findings are not persisted; the caller is
// responsible for that.
func (s *Scanner) Scan(targets []string) ([]finding.Finding, error) {
	if s.Config == "" {
		return nil, fmt.Errorf("sast: Scanner.Config is required (rules path or registry id)")
	}
	if len(targets) == 0 {
		return nil, nil
	}

	bin := s.Binary
	if bin == "" {
		bin = "opengrep"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("sast: opengrep binary %q not found in PATH: install it from https://github.com/opengrep/opengrep or set Scanner.Binary", bin)
	}

	// opengrep writes SARIF to a file, not stdout, so we use a tempfile.
	tmp, err := os.CreateTemp("", "zrok-opengrep-*.sarif")
	if err != nil {
		return nil, fmt.Errorf("sast: tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	args := s.buildArgs(tmpPath, targets)

	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stderr = &stderr
	// Opengrep exit codes vary: 0 = clean, 1 = findings (not an error from
	// our perspective), 2+ = various run problems (rules didn't parse,
	// language unsupported in the config, etc.). We don't blanket-fail on
	// non-zero — instead we try to parse whatever SARIF was written. A
	// partial scan is still useful, especially in mixed-language repos
	// where some configs apply and others don't.
	runErr := cmd.Run()
	var exitCode int
	if exitErr, ok := runErr.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if runErr != nil {
		// Non-exit error (couldn't launch process, etc.) — that's a real
		// problem; nothing was scanned.
		return nil, fmt.Errorf("sast: opengrep: %w", runErr)
	}

	data, readErr := os.ReadFile(tmpPath)
	if readErr != nil || len(data) == 0 {
		// No SARIF output AND opengrep exited non-zero — that's a real
		// failure; surface stderr so the user can act on it.
		if exitCode > 1 {
			return nil, fmt.Errorf("sast: opengrep exited %d with no SARIF output: %s", exitCode, strings.TrimSpace(stderr.String()))
		}
		return nil, nil
	}

	findings, parseErr := ParseSARIF(data)
	if parseErr != nil {
		if exitCode > 1 {
			return nil, fmt.Errorf("sast: opengrep exited %d and SARIF parse failed: %v (stderr: %s)", exitCode, parseErr, strings.TrimSpace(stderr.String()))
		}
		return nil, parseErr
	}
	// Relativize finding paths against ProjectRoot so downstream matching
	// (ground-truth comparison, dedup fingerprinting, SARIF code-scanning
	// ingest) doesn't see a path that varies with the working directory.
	// Opengrep SARIF emits absolute paths; without this, the same file
	// scanned from /tmp/repo-A vs /tmp/repo-B produces findings with
	// distinct .location.file values and they fail to dedup or match.
	if s.ProjectRoot != "" {
		for i := range findings {
			findings[i].Location.File = relativizePath(findings[i].Location.File, s.ProjectRoot)
		}
	}
	// Non-fatal exit code with usable SARIF: log a warning to stderr so the
	// caller knows opengrep complained about something, but return the
	// findings rather than aborting the whole run.
	if exitCode > 1 {
		fmt.Fprintf(os.Stderr, "warning: opengrep exited %d but produced %d finding(s); stderr: %s\n",
			exitCode, len(findings), strings.TrimSpace(stderr.String()))
	}
	return findings, nil
}

// buildArgs assembles the opengrep CLI arguments. Extracted so tests can
// inspect the merged --config list without invoking the binary.
func (s *Scanner) buildArgs(sarifOutPath string, targets []string) []string {
	args := []string{"scan", "--sarif-output=" + sarifOutPath, "--quiet", "--config", s.Config}
	for _, cfg := range s.ExtraConfigs {
		args = append(args, "--config", cfg)
	}
	args = append(args, s.ExtraArgs...)
	args = append(args, targets...)
	return args
}

// ParseSARIF converts an opengrep SARIF blob into zrok findings. Exposed so
// callers can drive opengrep separately (or feed in canned SARIF for tests).
func ParseSARIF(data []byte) ([]finding.Finding, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("sast: parse SARIF: %w", err)
	}

	var out []finding.Finding
	for _, run := range log.Runs {
		rulesByID := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			rulesByID[r.ID] = r
		}
		for _, result := range run.Results {
			f := convertResult(result, rulesByID)
			if f.Title == "" {
				continue
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func convertResult(r sarifResult, rules map[string]sarifRule) finding.Finding {
	rule := rules[r.RuleID]

	// Prefer the result message — it's the rule author's actual guidance.
	// opengrep populates rule.shortDescription with a synthetic
	// "Opengrep Finding: <ruleId>" string, which is useless as a title.
	description := strings.TrimSpace(r.Message.Text)
	if description == "" {
		description = strings.TrimSpace(rule.FullDescription.Text)
	}

	title := titleFor(rule, r.RuleID, description)

	severity := mapSeverity(r.Level)
	if rule.DefaultConfiguration != nil {
		// Rule-level severity is the better default when the result didn't
		// carry a level (some opengrep rules emit at message-only level).
		if r.Level == "" {
			severity = mapSeverity(rule.DefaultConfiguration.Level)
		}
	}

	var loc finding.Location
	if len(r.Locations) > 0 {
		pl := r.Locations[0].PhysicalLocation
		loc.File = filepath.Clean(pl.ArtifactLocation.URI)
		if pl.Region != nil {
			loc.LineStart = pl.Region.StartLine
			loc.LineEnd = pl.Region.EndLine
			if pl.Region.Snippet != nil {
				loc.Snippet = pl.Region.Snippet.Text
			}
		}
	}
	if loc.LineStart == 0 {
		loc.LineStart = 1
	}

	// opengrep encodes CWE in rule property tags with descriptive suffixes
	// like "CWE-327: Use of a Broken or Risky Cryptographic Algorithm" —
	// we want just the CWE-NNN identifier.
	cwe := ""
	for _, tag := range tagsOf(rule.Properties) {
		if id := extractCWE(tag); id != "" {
			cwe = id
			break
		}
	}

	// Tag the finding with the opengrep rule id that produced it. This is
	// what cmd/rule.go's audit path uses to attribute triggers and FPs
	// back to project-local rules by ID lookup.
	tags := []string{"sast", "opengrep"}
	if id := strings.TrimSpace(r.RuleID); id != "" {
		tags = append(tags, "opengrep-rule:"+id)
	}

	return finding.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  finding.ConfidenceMedium,
		Status:      finding.StatusOpen,
		CWE:         cwe,
		Location:    loc,
		Description: description,
		Remediation: strings.TrimSpace(rule.Help.Text),
		Tags:        tags,
		CreatedBy:   "opengrep",
	}
}

// OpengrepRuleTagPrefix is the prefix on a finding tag identifying the
// opengrep rule that produced it (e.g. "opengrep-rule:python.lang.security.xyz").
// Exposed so the rule package can scan finding tags and attribute triggers.
const OpengrepRuleTagPrefix = "opengrep-rule:"

// titleFor picks a short human-readable title. Preference order:
//
//  1. First sentence of the description (the rule's actual message).
//  2. shortDescription, unless it's opengrep's "Opengrep Finding: …" synthetic.
//  3. Last segment of the rule id (e.g. "insecure-hash-algorithm-md5").
func titleFor(rule sarifRule, ruleID, description string) string {
	if s := firstSentence(description); s != "" {
		return s
	}
	sd := strings.TrimSpace(rule.ShortDescription.Text)
	if sd != "" && !strings.HasPrefix(sd, "Opengrep Finding:") {
		return sd
	}
	parts := strings.Split(ruleID, ".")
	return parts[len(parts)-1]
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, ".!?"); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// extractCWE accepts opengrep-shaped tags and returns the canonical
// "CWE-<digits>" form. Returns "" when the tag isn't CWE-shaped.
func extractCWE(tag string) string {
	tag = strings.TrimSpace(tag)
	upper := strings.ToUpper(tag)
	if !strings.HasPrefix(upper, "CWE-") {
		return ""
	}
	// Walk past the digits; anything after (colon, space, description) is dropped.
	end := len(upper)
	for i := 4; i < len(upper); i++ {
		c := upper[i]
		if c < '0' || c > '9' {
			end = i
			break
		}
	}
	if end == 4 {
		// "CWE-" with no digits — invalid.
		return ""
	}
	return upper[:end]
}

// relativizePath converts an absolute path emitted by opengrep into a
// path relative to projectRoot, stripping URI prefixes opengrep
// occasionally includes (file://). When the path is already relative or
// can't be related to projectRoot (e.g. opengrep scanned a vendored
// rule pack outside the project tree), the cleaned absolute path is
// returned unchanged — callers that filter out-of-project findings (see
// cmd/sast.go) handle that case separately.
//
// Symlinks in the project path are resolved before relativization so
// the OWASP-eval pattern of running in macOS's /var/folders/... (a
// symlink to /private/var/folders/...) doesn't break the match.
func relativizePath(path, projectRoot string) string {
	cleaned := strings.TrimPrefix(path, "file://")
	cleaned = filepath.Clean(cleaned)
	if !filepath.IsAbs(cleaned) {
		return cleaned
	}
	if projectRoot == "" {
		return cleaned
	}
	rootAbs, err := filepath.Abs(projectRoot)
	if err != nil {
		return cleaned
	}
	// Resolve symlinks on the root so /var/folders/... matches
	// /private/var/folders/... when projectRoot was passed in symlink form.
	// EvalSymlinks fails for non-existent paths; if so we fall back to the
	// pre-resolution root.
	if resolved, errEval := filepath.EvalSymlinks(rootAbs); errEval == nil {
		rootAbs = resolved
	}
	// Same trick for the path itself — opengrep may emit the realpath
	// even when we passed in the symlink form, or vice versa.
	pathAbs := cleaned
	if resolved, errEval := filepath.EvalSymlinks(pathAbs); errEval == nil {
		pathAbs = resolved
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return cleaned
	}
	// If Rel had to walk up out of the project root, the file is
	// outside the project — keep the absolute form so the caller's
	// "out of project" filter (see cmd/sast.go) still rejects it.
	if strings.HasPrefix(rel, "..") {
		return cleaned
	}
	return rel
}

func mapSeverity(level string) finding.Severity {
	switch strings.ToLower(level) {
	case "error":
		return finding.SeverityHigh
	case "warning":
		return finding.SeverityMedium
	case "note":
		return finding.SeverityLow
	case "none", "":
		return finding.SeverityInfo
	default:
		return finding.SeverityMedium
	}
}

func tagsOf(props map[string]any) []string {
	raw, ok := props["tags"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Minimal SARIF input structs — only the fields we read. Kept separate from
// internal/finding/export/sarif.go so the output and input shapes can evolve
// independently.
type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool      `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                       `json:"id"`
	ShortDescription     sarifText                    `json:"shortDescription"`
	FullDescription      sarifText                    `json:"fullDescription"`
	Help                 sarifText                    `json:"help"`
	DefaultConfiguration *sarifReportingConfiguration `json:"defaultConfiguration"`
	Properties           map[string]any               `json:"properties"`
}

type sarifReportingConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifText        `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int          `json:"startLine"`
	EndLine   int          `json:"endLine"`
	Snippet   *sarifText   `json:"snippet"`
}

type sarifText struct {
	Text string `json:"text"`
}
