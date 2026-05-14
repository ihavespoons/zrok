package cmd

import (
	"strings"
	"testing"

	"github.com/ihavespoons/quokka/internal/finding"
)

func sampleFinding(id string, sev finding.Severity, title string) finding.Finding {
	return finding.Finding{
		ID:         id,
		Title:      title,
		Severity:   sev,
		Confidence: finding.ConfidenceHigh,
		Status:     finding.StatusConfirmed,
		CWE:        "CWE-89",
		Location: finding.Location{
			File:      "internal/db/q.go",
			LineStart: 42,
			LineEnd:   45,
			Function:  "GetUser",
		},
		Description: "User input flows into SQL query.",
		Impact:      "Full DB read.",
		Remediation: "Use parameterized queries.",
		CreatedBy:   "injection-agent",
	}
}

func TestRenderPRComment_NoFindings(t *testing.T) {
	out := renderPRComment(nil, 10, "", "")
	if !strings.Contains(out, "No security findings") {
		t.Errorf("expected all-clear message, got:\n%s", out)
	}
}

func TestRenderPRComment_SummaryCounts(t *testing.T) {
	findings := []finding.Finding{
		sampleFinding("F1", finding.SeverityCritical, "SQL Injection"),
		sampleFinding("F2", finding.SeverityHigh, "XSS"),
		sampleFinding("F3", finding.SeverityHigh, "Path Traversal"),
		sampleFinding("F4", finding.SeverityMedium, "Open Redirect"),
	}
	out := renderPRComment(findings, 10, "", "")
	if !strings.Contains(out, "Found **4** finding(s)") {
		t.Errorf("expected total count of 4, got:\n%s", out)
	}
	if !strings.Contains(out, "**1** critical") || !strings.Contains(out, "**2** high") || !strings.Contains(out, "**1** medium") {
		t.Errorf("expected severity breakdown, got:\n%s", out)
	}
}

func TestRenderPRComment_TopNTruncates(t *testing.T) {
	var findings []finding.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, sampleFinding("F", finding.SeverityHigh, "Issue"))
	}
	out := renderPRComment(findings, 2, "", "")
	if !strings.Contains(out, "and 3 more finding(s)") {
		t.Errorf("expected truncation footer, got:\n%s", out)
	}
	// Two numbered headings should appear.
	if strings.Count(out, "### 1. ") != 1 || strings.Count(out, "### 2. ") != 1 {
		t.Errorf("expected exactly 2 finding blocks, got:\n%s", out)
	}
	if strings.Contains(out, "### 3. ") {
		t.Errorf("third finding should not be rendered, got:\n%s", out)
	}
}

func TestRenderPRComment_SeverityThresholdFilters(t *testing.T) {
	findings := []finding.Finding{
		sampleFinding("F1", finding.SeverityCritical, "Bad"),
		sampleFinding("F2", finding.SeverityLow, "Style"),
		sampleFinding("F3", finding.SeverityInfo, "Note"),
	}
	out := renderPRComment(findings, 10, finding.SeverityHigh, "")
	if !strings.Contains(out, "### 1. [CRITICAL] Bad") {
		t.Errorf("expected critical finding to render, got:\n%s", out)
	}
	if strings.Contains(out, "[LOW]") || strings.Contains(out, "[INFO]") {
		t.Errorf("low/info should be filtered by threshold, got:\n%s", out)
	}
}

func TestRenderPRComment_ThresholdElidesAll(t *testing.T) {
	findings := []finding.Finding{
		sampleFinding("F1", finding.SeverityLow, "Style"),
		sampleFinding("F2", finding.SeverityInfo, "Note"),
	}
	out := renderPRComment(findings, 10, finding.SeverityHigh, "")
	if !strings.Contains(out, "below the `high` severity threshold") {
		t.Errorf("expected threshold-elision message, got:\n%s", out)
	}
}

func TestRenderPRComment_SarifLinkRendered(t *testing.T) {
	findings := []finding.Finding{sampleFinding("F1", finding.SeverityHigh, "Bad")}
	out := renderPRComment(findings, 10, "", "https://example.com/scan")
	if !strings.Contains(out, "(https://example.com/scan)") {
		t.Errorf("expected SARIF link, got:\n%s", out)
	}
}

func TestRenderFindingBlock_IncludesAllSections(t *testing.T) {
	f := sampleFinding("F1", finding.SeverityHigh, "SQL Injection")
	out := renderFindingBlock(1, f)
	mustContain := []string{
		"### 1. [HIGH] SQL Injection (CWE-89)",
		"`internal/db/q.go:42-45` in `GetUser`",
		"**What:** User input flows into SQL query.",
		"**Why it matters:** Full DB read.",
		"**Suggested fix:**",
		"Use parameterized queries.",
		"confidence: high",
		"agent: injection-agent",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("expected block to contain %q, got:\n%s", s, out)
		}
	}
}

func TestRenderFindingBlock_OmitsMissingFields(t *testing.T) {
	f := finding.Finding{
		Title:    "Bare finding",
		Severity: finding.SeverityMedium,
		Location: finding.Location{File: "a.go", LineStart: 1},
	}
	out := renderFindingBlock(1, f)
	if strings.Contains(out, "**Why it matters:**") {
		t.Errorf("should not render Why it matters when Impact is empty, got:\n%s", out)
	}
	if strings.Contains(out, "**Suggested fix:**") {
		t.Errorf("should not render Suggested fix when Remediation is empty, got:\n%s", out)
	}
	if !strings.Contains(out, "### 1. [MEDIUM] Bare finding") {
		t.Errorf("expected heading, got:\n%s", out)
	}
}
