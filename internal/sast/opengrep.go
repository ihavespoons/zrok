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

	// ExtraArgs are passed through to opengrep scan, after the standard
	// SARIF + quiet flags. Use sparingly — most behavior should be exposed
	// via dedicated fields.
	ExtraArgs []string
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
	tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{"scan", "--sarif-output=" + tmpPath, "--quiet", "--config", s.Config}
	args = append(args, s.ExtraArgs...)
	args = append(args, targets...)

	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stderr = &stderr
	// Opengrep exit codes: 0 = no findings, 1 = findings present (not an
	// error from our perspective), other = real failure. cmd.Run treats any
	// non-zero exit as ExitError, so we inspect rather than blanket-fail.
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() > 1 {
				return nil, fmt.Errorf("sast: opengrep exited %d: %s", exitErr.ExitCode(), strings.TrimSpace(stderr.String()))
			}
		} else {
			return nil, fmt.Errorf("sast: opengrep: %w", err)
		}
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("sast: read SARIF output: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return ParseSARIF(data)
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
	rule, _ := rules[r.RuleID]

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

	return finding.Finding{
		Title:       title,
		Severity:    severity,
		Confidence:  finding.ConfidenceMedium,
		Status:      finding.StatusOpen,
		CWE:         cwe,
		Location:    loc,
		Description: description,
		Remediation: strings.TrimSpace(rule.Help.Text),
		Tags:        []string{"sast", "opengrep"},
		CreatedBy:   "opengrep",
	}
}

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
