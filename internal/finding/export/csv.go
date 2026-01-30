package export

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/ihavespoons/zrok/internal/finding"
)

// CSVExporter exports findings to CSV format
type CSVExporter struct {
	toolName    string
	toolVersion string
	projectName string
}

// NewCSVExporter creates a new CSV exporter
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{
		toolName:    "zrok",
		toolVersion: "1.0.0",
	}
}

// SetProjectName sets the project name for the report
func (e *CSVExporter) SetProjectName(name string) {
	e.projectName = name
}

// Export exports findings to CSV format
func (e *CSVExporter) Export(findings []finding.Finding) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header row
	headers := []string{
		"ID",
		"Title",
		"Severity",
		"Confidence",
		"Status",
		"CWE",
		"CVSS Score",
		"CVSS Vector",
		"File",
		"Line Start",
		"Line End",
		"Function",
		"Description",
		"Impact",
		"Remediation",
		"Tags",
		"References",
		"Created At",
		"Created By",
	}
	if err := w.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	// Data rows
	for _, f := range findings {
		cvssScore := ""
		cvssVector := ""
		if f.CVSS != nil {
			cvssScore = fmt.Sprintf("%.1f", f.CVSS.Score)
			cvssVector = f.CVSS.Vector
		}

		lineStart := ""
		lineEnd := ""
		if f.Location.LineStart > 0 {
			lineStart = fmt.Sprintf("%d", f.Location.LineStart)
		}
		if f.Location.LineEnd > 0 {
			lineEnd = fmt.Sprintf("%d", f.Location.LineEnd)
		}

		row := []string{
			f.ID,
			f.Title,
			string(f.Severity),
			string(f.Confidence),
			string(f.Status),
			f.CWE,
			cvssScore,
			cvssVector,
			f.Location.File,
			lineStart,
			lineEnd,
			f.Location.Function,
			f.Description,
			f.Impact,
			f.Remediation,
			strings.Join(f.Tags, "; "),
			strings.Join(f.References, "; "),
			f.CreatedAt.Format("2006-01-02 15:04:05"),
			f.CreatedBy,
		}

		if err := w.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("CSV write error: %w", err)
	}

	return buf.Bytes(), nil
}

// ContentType returns the MIME type for CSV
func (e *CSVExporter) ContentType() string {
	return "text/csv"
}

// FileExtension returns the file extension for CSV
func (e *CSVExporter) FileExtension() string {
	return ".csv"
}

// FormatName returns the format name
func (e *CSVExporter) FormatName() string {
	return "csv"
}
