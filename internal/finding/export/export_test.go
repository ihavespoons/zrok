package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
)

func createTestFindings() []finding.Finding {
	return []finding.Finding{
		{
			ID:          "FIND-001",
			Title:       "SQL Injection",
			Severity:    finding.SeverityCritical,
			Confidence:  finding.ConfidenceHigh,
			Status:      finding.StatusOpen,
			CWE:         "CWE-89",
			CVSS:        &finding.CVSS{Score: 9.8, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			Description: "SQL injection in user query",
			Impact:      "Full database compromise",
			Remediation: "Use parameterized queries",
			Location: finding.Location{
				File:      "src/db/queries.go",
				LineStart: 42,
				LineEnd:   45,
				Function:  "GetUser",
				Snippet:   "query := fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id)",
			},
			Evidence: []finding.Evidence{
				{Type: "dataflow", Description: "User input flows to SQL query"},
			},
			References: []string{"https://owasp.org/sql-injection"},
			Tags:       []string{"injection", "database"},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
			CreatedBy:  "test-agent",
		},
		{
			ID:          "FIND-002",
			Title:       "XSS Vulnerability",
			Severity:    finding.SeverityHigh,
			Confidence:  finding.ConfidenceMedium,
			Status:      finding.StatusConfirmed,
			CWE:         "CWE-79",
			Description: "Reflected XSS in search",
			Remediation: "Escape HTML output",
			Location: finding.Location{
				File:      "src/handlers/search.go",
				LineStart: 100,
			},
			Tags:      []string{"xss", "web"},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}

func TestGetExporter(t *testing.T) {
	tests := []struct {
		format  string
		wantErr bool
	}{
		{"sarif", false},
		{"json", false},
		{"md", false},
		{"markdown", false},
		{"html", false},
		{"csv", false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			exp, err := GetExporter(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if exp == nil {
					t.Error("exporter is nil")
				}
			}
		})
	}
}

func TestSARIFExport(t *testing.T) {
	findings := createTestFindings()
	exporter := NewSARIFExporter()

	data, err := exporter.Export(findings)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify it's valid JSON
	var sarif SarifLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Check structure
	if sarif.Version != "2.1.0" {
		t.Errorf("unexpected version: %s", sarif.Version)
	}

	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}

	run := sarif.Runs[0]
	if run.Tool.Driver.Name != "zrok" {
		t.Errorf("unexpected tool name: %s", run.Tool.Driver.Name)
	}

	if len(run.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(run.Results))
	}

	// Check first result
	result := run.Results[0]
	if result.RuleID != "CWE-89" {
		t.Errorf("unexpected rule ID: %s", result.RuleID)
	}
	if result.Level != "error" {
		t.Errorf("unexpected level: %s", result.Level)
	}

	// Check location
	if len(result.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(result.Locations))
	}
	loc := result.Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != "src/db/queries.go" {
		t.Errorf("unexpected file: %s", loc.PhysicalLocation.ArtifactLocation.URI)
	}

	// Verify content type
	if exporter.ContentType() != "application/sarif+json" {
		t.Errorf("unexpected content type: %s", exporter.ContentType())
	}

	// Verify extension
	if exporter.FileExtension() != ".sarif" {
		t.Errorf("unexpected extension: %s", exporter.FileExtension())
	}
}

func TestJSONExport(t *testing.T) {
	findings := createTestFindings()
	exporter := NewJSONExporter()
	exporter.SetProjectName("test-project")

	data, err := exporter.Export(findings)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Parse the output
	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Check metadata
	if report.Metadata.Tool != "zrok" {
		t.Errorf("unexpected tool: %s", report.Metadata.Tool)
	}
	if report.Metadata.ProjectName != "test-project" {
		t.Errorf("unexpected project: %s", report.Metadata.ProjectName)
	}

	// Check summary
	if report.Summary.Total != 2 {
		t.Errorf("unexpected total: %d", report.Summary.Total)
	}
	if report.Summary.BySeverity["critical"] != 1 {
		t.Errorf("unexpected critical count: %d", report.Summary.BySeverity["critical"])
	}

	// Check findings
	if len(report.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(report.Findings))
	}

	// Verify content type
	if exporter.ContentType() != "application/json" {
		t.Errorf("unexpected content type: %s", exporter.ContentType())
	}
}

func TestMarkdownExport(t *testing.T) {
	findings := createTestFindings()
	exporter := NewMarkdownExporter()
	exporter.SetProjectName("test-project")

	data, err := exporter.Export(findings)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	content := string(data)

	// Check header
	if !strings.Contains(content, "Security Findings Report: test-project") {
		t.Error("missing project name in title")
	}

	// Check summary
	if !strings.Contains(content, "**Total Findings:** 2") {
		t.Error("missing total findings")
	}

	// Check severity table
	if !strings.Contains(content, "| Severity | Count |") {
		t.Error("missing severity table")
	}

	// Check finding details
	if !strings.Contains(content, "SQL Injection") {
		t.Error("missing finding title")
	}
	if !strings.Contains(content, "CWE-89") {
		t.Error("missing CWE")
	}
	if !strings.Contains(content, "src/db/queries.go") {
		t.Error("missing file location")
	}

	// Check code block
	if !strings.Contains(content, "```") {
		t.Error("missing code block")
	}

	// Check remediation
	if !strings.Contains(content, "Use parameterized queries") {
		t.Error("missing remediation")
	}

	// Verify content type
	if exporter.ContentType() != "text/markdown" {
		t.Errorf("unexpected content type: %s", exporter.ContentType())
	}
}

func TestHTMLExport(t *testing.T) {
	findings := createTestFindings()
	exporter := NewHTMLExporter()
	exporter.SetProjectName("test-project")

	data, err := exporter.Export(findings)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	content := string(data)

	// Check HTML structure
	if !strings.Contains(content, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(content, "<html") {
		t.Error("missing html tag")
	}

	// Check title
	if !strings.Contains(content, "test-project") {
		t.Error("missing project name")
	}

	// Check findings
	if !strings.Contains(content, "SQL Injection") {
		t.Error("missing finding title")
	}
	if !strings.Contains(content, "severity-critical") {
		t.Error("missing severity class")
	}

	// Check stats
	if !strings.Contains(content, "stat-card") {
		t.Error("missing stats")
	}

	// Verify content type
	if exporter.ContentType() != "text/html" {
		t.Errorf("unexpected content type: %s", exporter.ContentType())
	}
}

func TestCSVExport(t *testing.T) {
	findings := createTestFindings()
	exporter := NewCSVExporter()

	data, err := exporter.Export(findings)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Check header
	if !strings.HasPrefix(lines[0], "ID,Title,Severity") {
		t.Error("missing or incorrect header")
	}

	// Check we have data rows (header + 2 findings + possible empty line)
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines, got %d", len(lines))
	}

	// Check first data row contains expected content
	if !strings.Contains(lines[1], "FIND-001") {
		t.Error("missing finding ID")
	}
	if !strings.Contains(lines[1], "SQL Injection") {
		t.Error("missing finding title")
	}
	if !strings.Contains(lines[1], "critical") {
		t.Error("missing severity")
	}

	// Verify content type
	if exporter.ContentType() != "text/csv" {
		t.Errorf("unexpected content type: %s", exporter.ContentType())
	}
}

func TestExportFindings(t *testing.T) {
	findings := createTestFindings()

	formats := []string{"sarif", "json", "md", "html", "csv"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			data, err := ExportFindings(findings, format, "test-project")
			if err != nil {
				t.Fatalf("ExportFindings failed: %v", err)
			}
			if len(data) == 0 {
				t.Error("empty output")
			}
		})
	}
}

func TestEmptyExport(t *testing.T) {
	var findings []finding.Finding

	formats := []string{"sarif", "json", "md", "html", "csv"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			data, err := ExportFindings(findings, format, "")
			if err != nil {
				t.Fatalf("ExportFindings failed: %v", err)
			}
			if len(data) == 0 {
				t.Error("empty output for empty findings")
			}
		})
	}
}

func TestSARIFSeverityMapping(t *testing.T) {
	exporter := NewSARIFExporter()

	tests := []struct {
		severity finding.Severity
		expected string
	}{
		{finding.SeverityCritical, "error"},
		{finding.SeverityHigh, "error"},
		{finding.SeverityMedium, "warning"},
		{finding.SeverityLow, "note"},
		{finding.SeverityInfo, "note"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			findings := []finding.Finding{
				{
					ID:       "TEST",
					Title:    "Test",
					Severity: tt.severity,
					Location: finding.Location{File: "test.go", LineStart: 1},
				},
			}

			data, _ := exporter.Export(findings)
			var sarif SarifLog
			json.Unmarshal(data, &sarif)

			if sarif.Runs[0].Results[0].Level != tt.expected {
				t.Errorf("expected level %s, got %s", tt.expected, sarif.Runs[0].Results[0].Level)
			}
		})
	}
}
