package export

import (
	"encoding/json"
	"time"

	"github.com/ihavespoons/zrok/internal/finding"
)

// JSONReport represents a JSON export report
type JSONReport struct {
	Metadata JSONMetadata      `json:"metadata"`
	Summary  JSONSummary       `json:"summary"`
	Findings []finding.Finding `json:"findings"`
}

// JSONMetadata contains report metadata
type JSONMetadata struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	ProjectName string   `json:"project_name,omitempty"`
}

// JSONSummary contains summary statistics
type JSONSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
}

// JSONExporter exports findings to JSON format
type JSONExporter struct {
	toolName    string
	toolVersion string
	projectName string
}

// NewJSONExporter creates a new JSON exporter
func NewJSONExporter() *JSONExporter {
	return &JSONExporter{
		toolName:    "zrok",
		toolVersion: "1.0.0",
	}
}

// SetProjectName sets the project name for the report
func (e *JSONExporter) SetProjectName(name string) {
	e.projectName = name
}

// Export exports findings to JSON format
func (e *JSONExporter) Export(findings []finding.Finding) ([]byte, error) {
	// Build summary
	summary := JSONSummary{
		Total:      len(findings),
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	for _, f := range findings {
		summary.BySeverity[string(f.Severity)]++
		summary.ByStatus[string(f.Status)]++
	}

	report := JSONReport{
		Metadata: JSONMetadata{
			Tool:        e.toolName,
			Version:     e.toolVersion,
			GeneratedAt: time.Now(),
			ProjectName: e.projectName,
		},
		Summary:  summary,
		Findings: findings,
	}

	return json.MarshalIndent(report, "", "  ")
}

// ContentType returns the MIME type for JSON
func (e *JSONExporter) ContentType() string {
	return "application/json"
}

// FileExtension returns the file extension for JSON
func (e *JSONExporter) FileExtension() string {
	return ".json"
}

// FormatName returns the format name
func (e *JSONExporter) FormatName() string {
	return "json"
}
